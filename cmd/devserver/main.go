// Command devserver runs the whole platform on one machine so it can be
// looked at.
//
// It is a DEMONSTRATION, not a deployment, and the differences are
// deliberate and visible rather than hidden:
//
//   - the identity provider is local and asks for no password, where a real
//     tenant signs in against their own Microsoft Entra or Google Workspace
//   - cookies are sent without the Secure attribute, because this serves
//     plain HTTP on localhost
//   - the three signing keys are fixed strings in this file rather than
//     coming from a vault
//   - a tenant is seeded with invented devices, policies and history
//
// None of those shortcuts exists in the gateway itself. This file supplies
// them from outside, which is the point: cmd/gateway is the real entry point
// and refuses to start without the things this one fakes.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"platform/internal/android"
	"platform/internal/branding"
	"platform/internal/command"
	"platform/internal/data"
	"platform/internal/directory"
	"platform/internal/enrol"
	"platform/internal/gateway"
	"platform/internal/identity"
	"platform/internal/identity/idptest"
	"platform/internal/notify"
	"platform/internal/secrets"
	"platform/internal/session"
	"platform/internal/tenantclaim"
)

// Ports are configurable because a developer machine often already has
// something on 8080, and the issuer and the redirect address both have to
// agree with whatever is chosen.
//
// The browser and the gateway both have to reach the identity provider, and
// 127.0.0.1 is the one address that means the same thing on the host and
// inside the container. It is also what the schema's issuer check allows for
// local development.
var (
	consolePort = portOr("MDM_CONSOLE_PORT", "8090")
	idpPort     = portOr("MDM_IDP_PORT", "8091")
	consoleAddr = ":" + consolePort
	// Google will only send an administrator back to https. The console is
	// plain http here, so a second listener, with a certificate made at
	// startup, answers the one URL Google needs to be https.
	consoleTLSPort = portOr("MDM_CONSOLE_TLS_PORT", "8092")
	consoleTLSAt   = "https://localhost:" + consoleTLSPort
	idpAddr        = ":" + idpPort
	idpIssuer      = "http://127.0.0.1:" + idpPort
	consoleAt      = "http://localhost:" + consolePort
	signupAt       = "http://signup.localhost:" + consolePort + "/signup"
	fakeGooglePort = portOr("MDM_FAKE_GOOGLE_PORT", "8093")
	fakeGoogleAt   = "http://localhost:" + fakeGooglePort
)

func portOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

var (
	tenantID = uuid.MustParse("11111111-1111-1111-1111-111111111111")
	claimKey = []byte("devserver-claim-signing-key-32-bytes")
	sessKey  = []byte("devserver-session-signing-key-32byte")
	sealKey  = []byte("devserver-sealing-key-32-bytes!!")
)

// people are the accounts the local provider offers. The groups are what a
// real Entra tenant would send; tenant_role_map below turns them into roles,
// exactly as it would in a deployment.
var people = []idptest.Person{
	{Subject: "f.okonkwo", Name: "F. Okonkwo", Email: "f.okonkwo@kalesi.example",
		Groups: []string{"All-Staff", "MDM-Owners"}},
	{Subject: "o.martins", Name: "O. Martins", Email: "o.martins@kalesi.example",
		Groups: []string{"All-Staff", "IT-Operations"}},
	{Subject: "d.adeyinka", Name: "D. Adeyinka", Email: "d.adeyinka@kalesi.example",
		Groups: []string{"All-Staff", "Security-Team"}},
	{Subject: "p.eneh", Name: "P. Eneh", Email: "p.eneh@kalesi.example",
		Groups: []string{"All-Staff", "Service-Desk"}},
	{Subject: "r.chukwu", Name: "R. Chukwu", Email: "r.chukwu@kalesi.example",
		Groups: []string{"All-Staff", "Internal-Audit"}},
	{Subject: "t.eze", Name: "T. Eze", Email: "t.eze@kalesi.example",
		Groups: []string{"All-Staff"}},
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx := context.Background()

	fail := func(msg string, err error) {
		log.Error(msg, "err", err)
		os.Exit(1)
	}
	must := func(name string) string {
		v := os.Getenv(name)
		if v == "" {
			fail("missing environment variable: "+name, nil)
		}
		return v
	}

	idp, err := idptest.NewHandler("kalesi-console", idpIssuer)
	if err != nil {
		fail("identity provider", err)
	}
	idp.Interactive = true
	idp.People = people

	master, err := secrets.NewAESSealer(sealKey)
	if err != nil {
		fail("sealer", err)
	}
	sealer := secrets.NewKeyring(master)
	if err := seed(ctx, must("MDM_ADMIN_DSN"), master, log); err != nil {
		fail("seeding the demonstration tenant", err)
	}

	signer, err := tenantclaim.NewSigner(claimKey)
	if err != nil {
		fail("claim signer", err)
	}
	sessions, err := session.NewSigner(sessKey)
	if err != nil {
		fail("session signer", err)
	}
	store, err := data.Open(ctx, must("MDM_APP_DSN"), signer, 16)
	if err != nil {
		fail("database", err)
	}
	defer store.Close()
	dir, err := directory.Open(ctx, must("MDM_OPERATOR_DSN"))
	if err != nil {
		fail("directory", err)
	}
	defer dir.Close()

	// The demonstration has no chat channel, so everything is pointed at
	// this platform's own log. An operator watching the terminal sees the
	// notifications arrive, which is the honest version of "somebody was
	// told" on a machine with no Slack.
	webhook := notify.NewWebhook(log)
	webhook.AllowPrivateAddresses = true
	// No mail server on a laptop, so the demonstration gets the log
	// channel and says so, rather than offering email that goes nowhere.
	syslogCh := notify.NewSyslog()
	syslogCh.AllowPrivateAddresses = true
	jira := notify.NewTicketing("jira", log)
	jira.AllowPrivateAddresses = true
	snow := notify.NewTicketing("servicenow", log)
	snow.AllowPrivateAddresses = true
	notifier := notify.New(sealer, webhook, notify.NewLog(log), syslogCh, jira, snow)
	worker := notify.NewWorker(notifier, store, signer, dir.ActiveTenantIDs, log)
	worker.Every = 5 * time.Second
	go worker.Run(ctx)

	// A fake of Google's Android Management API, in this process, so the
	// demonstration can bind an enterprise and enrol a device with no
	// Google account in the room. The real client is the same code
	// pointed at Google.
	//
	// With MDM_ANDROID_CREDENTIALS_FILE set, the real one is used instead:
	// the same client cmd/gateway builds, so the first real bind can be
	// walked on a laptop before anything is deployed. The fake still runs
	// (its pretend phone is harmless), but nothing is pointed at it.
	fakeGoogle, err := android.NewFakeGoogleOn(":"+fakeGooglePort, fakeGoogleAt)
	if err != nil {
		fail("fake google", err)
	}
	var androidAPI android.Provider = fakeGoogle.Client()
	androidNote := "a fake of Google's API runs in here: bind it,\n                  make a token, then \"enrol\" a phone at " + fakeGoogleAt + "/phone"
	if path := os.Getenv("MDM_ANDROID_CREDENTIALS_FILE"); path != "" {
		creds, err := os.ReadFile(path)
		if err != nil {
			fail("MDM_ANDROID_CREDENTIALS_FILE", err)
		}
		real, err := android.NewAMAPI(ctx, creds)
		if err != nil {
			fail("android credentials", err)
		}
		androidAPI = real
		androidNote = "REAL Google, with the service account in\n                  " + path + ": bind it, make a token, scan it on a phone"
	}

	g := gateway.New(gateway.Config{
		Directory: dir, Store: store, Signer: signer,
		Sessions: sessions, OIDC: identity.NewOIDC(), SAML: identity.NewSAML(), Sealer: sealer,
		Enrol: enrol.New(sealer), Notify: notifier, Android: androidAPI,
		// No mail server on a laptop: an invitation is printed to this log.
		Mail:                notify.NewLog(log),
		AndroidCallbackBase: consoleTLSAt,
		Pipeline: command.New(&command.StoredKeys{Sealer: sealer},
			command.ByOS{
				Routes:   map[string]command.PushProvider{"android": android.Push{Provider: androidAPI}},
				Fallback: command.AppleNotConfigured(),
			}, command.DefaultLimiter()),
		CSRFKey: claimKey, Log: log,
		// Plain HTTP on localhost, so a Secure cookie would never come back.
		InsecureCookies: true,
		// Sign-up on its own hostname. Browsers resolve *.localhost to this
		// machine without an /etc/hosts entry, so a tenant that signs up as
		// "arbor" answers at arbor.localhost. There is no mail server, so
		// the verification link is printed to this log instead.
		Signup: &gateway.SignupConfig{
			Host: "signup.localhost", TenantDomain: "localhost",
			Brand: branding.Brand{ProductName: "Device Care", Colour: "#1F4E79", MarkLetter: "D",
				LegalFooter: "Local demonstration"},
			Mail: notify.NewLog(log),
		},
	})

	go func() {
		srv := &http.Server{Addr: idpAddr, Handler: idp.Handler(),
			ReadHeaderTimeout: 10 * time.Second}
		if err := srv.ListenAndServe(); err != nil {
			fail("identity provider", err)
		}
	}()

	// Fast, so the demonstration shows the warning rather than describing
	// it. A deployment runs this daily.
	go g.RunWake(ctx)
	go g.RunExpirySweep(ctx, dir.ActiveTenantIDs, 30*time.Second)
	go g.RunWeeklyReport(ctx, dir.ActiveTenantIDs, dir.PrimaryHost, 30*time.Second)
	go g.RunSIEMExport(ctx, dir.ActiveTenantIDs, dir.SlugOf, 15*time.Second)

	banner(androidNote)
	go func() {
		cert, err := selfSigned()
		if err != nil {
			fail("self-signed certificate", err)
		}
		tlsSrv := &http.Server{Addr: ":" + consoleTLSPort, Handler: g.Handler(),
			TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
			ReadHeaderTimeout: 10 * time.Second}
		if err := tlsSrv.ListenAndServeTLS("", ""); err != nil {
			fail("console (https)", err)
		}
	}()

	srv := &http.Server{Addr: consoleAddr, Handler: g.Handler(),
		ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		fail("console", err)
	}
}

// selfSigned makes a certificate for localhost that lives as long as this
// process is likely to. The browser will warn once on the way back from
// Google; the banner says so. Nothing outside this machine ever sees it.
func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func banner(androidNote string) {
	fmt.Printf(`
  ────────────────────────────────────────────────────────────────────
   Kalesi Device Care  ·  local demonstration

   Console        %s
   Sign in        %s/signin
   Sign up        %s  (a new tenant; the email link is printed here)
   Android        %s/android  (%s)
                  Google sends you back over https, to %s: the browser
                  warns once about this machine's own certificate; proceed.

   The sign-in page offers six accounts with no password. That stands
   in for the tenant's own Microsoft Entra directory, which is where a
   real deployment would send you. Pick different people to watch the
   console change: a Service Desk account sees fewer sections than an
   IT Operations one, and the controls it may not use are absent
   rather than greyed out.

   Nothing here can reach a real device. The Apple vendor certificate
   is not in place, so commands queue and say so.
  ────────────────────────────────────────────────────────────────────

`, consoleAt, consoleAt, signupAt, consoleAt, androidNote, consoleTLSAt)
}

// seed builds a tenant that looks like it has been running for a while,
// because an empty console shows nothing about how the product behaves.
func seed(ctx context.Context, dsn string, sealer *secrets.AESSealer, log *slog.Logger) error {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	sealed, err := sealer.Seal([]byte("the-demo-client-secret"))
	if err != nil {
		return err
	}

	// With a real Google in play the enterprise this tenant bound is real,
	// and a restart must not forget it: an enterprise forgotten here is an
	// orphan at Google, and the next bind makes a second one. The fake's
	// rows are worthless and are wiped like the rest.
	keepAndroid := os.Getenv("MDM_ANDROID_CREDENTIALS_FILE") != ""
	wipeAndroid := []string{
		`DELETE FROM android_enrollment_tokens`,
		`DELETE FROM android_enterprises`,
	}
	if keepAndroid {
		wipeAndroid = nil
		log.Info("keeping the Android enterprise across this restart")
	}
	statements := []string{
		`DELETE FROM device_apps`,
		`DELETE FROM device_recovery_keys`,
		`DELETE FROM device_compliance`,
		`DELETE FROM device_certificates`,
		`DELETE FROM enrolments`,
		`DELETE FROM tenant_ca`,
		`DELETE FROM command_approvals`,
		`DELETE FROM commands`,
		`DELETE FROM audit_events`,
		`DELETE FROM devices`,
		`DELETE FROM policies`,
		`DELETE FROM tenant_branding`,
		`DELETE FROM integration_tokens`,
		`DELETE FROM siem_cursors`,
		`DELETE FROM tenant_keys`,
		`DELETE FROM tenant_admins`,
		`DELETE FROM command_signing_keys`,
		`DELETE FROM api_rate`,
		`DELETE FROM tenant_domains`,
		`DELETE FROM tenant_role_map`,
		`DELETE FROM tenant_identity`,
	}
	statements = append(statements, wipeAndroid...)
	statements = append(statements,
		// The tenant row is kept, not replaced: the Android rows above may
		// still point at it.
		`INSERT INTO tenants (id, name, slug, plan, status, api_rate_per_min, device_cap, admin_seats) VALUES
		   ('11111111-1111-1111-1111-111111111111','Kalesi Foods','kalesi','growth','active',6000,500,10)
		 ON CONFLICT (id) DO UPDATE SET name = excluded.name, slug = excluded.slug, plan = excluded.plan,
		   status = excluded.status, api_rate_per_min = excluded.api_rate_per_min,
		   device_cap = excluded.device_cap, admin_seats = excluded.admin_seats`,
		// Both spellings, so either address in the browser finds the tenant.
		`INSERT INTO tenant_domains (host, tenant_id, verified_at) VALUES
		   ('localhost','11111111-1111-1111-1111-111111111111', now()),
		   ('127.0.0.1','11111111-1111-1111-1111-111111111111', now())`,
		// T12: the console wears the tenant's name, never ours.
		`INSERT INTO tenant_branding (tenant_id, product_name, legal_footer, brand_colour, mark_letter)
		 VALUES ('11111111-1111-1111-1111-111111111111','Kalesi Device Care',
		         'Kalesi Foods Ltd · RC 1184420 · Lagos','#0F6E66','K')`,

		`INSERT INTO devices (tenant_id, name, serial, os_family, ownership, state, last_report_at) VALUES
		   ('11111111-1111-1111-1111-111111111111','HQ-MBP-001','C02XK4YTQ6NV','macos','company','compliant', now() - interval '2 hours'),
		   ('11111111-1111-1111-1111-111111111111','HQ-MBP-002','C02XK4YTQ71W','macos','company','not_compliant', now() - interval '40 minutes'),
		   ('11111111-1111-1111-1111-111111111111','HQ-WIN-004','SN-00000004','windows','company','compliant', now() - interval '5 hours'),
		   ('11111111-1111-1111-1111-111111111111','FIELD-IPH-009','SN-00000009','ios','company','state_unknown', now() - interval '19 days'),
		   ('11111111-1111-1111-1111-111111111111','Ade personal phone','SN-BYOD-0021','android','personal','compliant', now() - interval '1 hour'),
		   ('11111111-1111-1111-1111-111111111111','HQ-MBP-OLD-7','C02XK4YTOLD7','macos','company','quarantined', now() - interval '3 days'),
		   ('11111111-1111-1111-1111-111111111111','STORE-WIN-011','SN-00000011','windows','company','awaiting_first_boot', NULL)`,
	)
	for _, s := range statements {
		if _, err := conn.Exec(ctx, s); err != nil {
			return fmt.Errorf("%.60s: %w", s, err)
		}
	}

	// Identity: the local provider, and the group mapping a real tenant
	// would fill in during setup.
	if _, err := conn.Exec(ctx, `
		INSERT INTO tenant_identity
		  (tenant_id, issuer, client_id, client_secret_sealed, redirect_url, role_claim)
		VALUES ($1, $2, 'kalesi-console', $3, $4, 'groups')`,
		tenantID, idpIssuer, sealed, consoleAt+"/signin/callback"); err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO tenant_role_map (tenant_id, claim_value, role) VALUES
		  ($1,'MDM-Owners','super_admin'),
		  ($1,'IT-Operations','it_admin'),
		  ($1,'Security-Team','security_manager'),
		  ($1,'Service-Desk','helpdesk'),
		  ($1,'Internal-Audit','auditor'),
		  ($1,'All-Staff','employee')`, tenantID); err != nil {
		return err
	}

	// Two policies, so the strictest-wins merge is visible on a device page
	// rather than only described.
	for _, p := range []struct{ name, scope, body string }{
		{"Baseline", "", `{"passcode_required": true, "passcode_min_length": 8,
		   "disk_encryption_required": true, "screen_lock_timeout_max": 300}`},
		{"Finance laptops", "macos", `{"passcode_min_length": 14, "os_version_min": "15.0",
		   "firewall_required": true}`},
		{"Personal devices", "", `{"jailbreak_blocked": true}`},
	} {
		var scope any
		if p.scope != "" {
			scope = p.scope
		}
		if _, err := conn.Exec(ctx, `
			INSERT INTO policies (tenant_id, name, version, body, scope_os_family, active, created_by)
			VALUES ($1, $2, 1, $3::jsonb, $4, true, 'o.martins')`,
			tenantID, p.name, p.body, scope); err != nil {
			return fmt.Errorf("policy %s: %w", p.name, err)
		}
	}
	// A superseded version, so the "what did we require in March" story is
	// on the page.
	// Two statements, two calls: pgx prepares each one, so a semicolon in
	// the middle is a syntax error rather than a batch.
	if _, err := conn.Exec(ctx,
		`UPDATE policies SET active = false WHERE name = 'Baseline'`); err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO policies (tenant_id, name, version, body, active, created_by)
		VALUES ($1,'Baseline',2,'{"passcode_required": true, "passcode_min_length": 10,
		        "disk_encryption_required": true, "screen_lock_timeout_max": 300}'::jsonb,
		        true,'o.martins')`, tenantID); err != nil {
		return err
	}

	// Verdicts to match the states above. Without these the list would say
	// a device is failing while its own page said it had never reported,
	// which is exactly the kind of disagreement this schema is shaped to
	// make impossible in the real path.
	//
	// The merged requirement for a company Mac is Baseline v2 and Finance
	// laptops v1 together, so the strictest of each: a passcode of at least
	// 14, an encrypted disk, a lock within 300 seconds, macOS 15.0 or
	// later, a firewall, and no jailbreak.
	type verdict struct{ device, state, report, findings, policies string }
	macPolicies := `["Baseline v2","Finance laptops v1","Personal devices v1"]`
	restPolicies := `["Baseline v2","Personal devices v1"]`
	good := `{"passcode_set":true,"passcode_length":16,"disk_encryption":true,
	          "screen_lock_timeout":120,"os_version":"15.2","firewall":true,"jailbroken":false}`

	for _, v := range []verdict{
		{"HQ-MBP-001", "compliant", good, `[]`, macPolicies},
		{"HQ-MBP-002", "not_compliant",
			`{"passcode_set":true,"passcode_length":8,"disk_encryption":true,
			  "screen_lock_timeout":600,"os_version":"14.6","firewall":false,"jailbroken":false}`,
			`[{"kind":"passcode_min_length","rule":"the passcode must be at least 14 characters",
			   "saw":"the passcode is 8 characters","from":"Finance laptops v1"},
			  {"kind":"screen_lock_timeout_max","rule":"the screen must lock within 300 seconds",
			   "saw":"it locks after 600 seconds","from":"Baseline v2"},
			  {"kind":"os_version_min","rule":"the operating system must be at least version 15.0",
			   "saw":"it is on 14.6","from":"Finance laptops v1"},
			  {"kind":"firewall_required","rule":"the firewall must be on",
			   "saw":"the firewall is off","from":"Finance laptops v1"}]`,
			macPolicies},
		{"HQ-WIN-004", "compliant",
			`{"passcode_set":true,"passcode_length":12,"disk_encryption":true,
			  "screen_lock_timeout":180,"os_version":"11.0","jailbroken":false}`,
			`[]`, restPolicies},
		{"Ade personal phone", "compliant",
			`{"passcode_set":true,"passcode_length":10,"disk_encryption":true,
			  "screen_lock_timeout":60,"os_version":"15","jailbroken":false}`,
			`[]`, restPolicies},
		// Reported nineteen days ago. The stored verdict was a pass; the
		// console re-checks staleness when anyone looks, so it reads as
		// unknown rather than as a green row for a phone nobody has heard
		// from since the third of October.
		{"FIELD-IPH-009", "compliant", good, `[]`, restPolicies},
		// Quarantined by a person. The verdict underneath is still honest
		// about what the machine reported, and the state is not touched.
		{"HQ-MBP-OLD-7", "not_compliant",
			`{"passcode_set":false,"disk_encryption":false,"os_version":"12.1","jailbroken":false}`,
			`[{"kind":"passcode_required","rule":"a passcode must be set",
			   "saw":"no passcode is set","from":"Baseline v2"},
			  {"kind":"disk_encryption_required","rule":"the disk must be encrypted",
			   "saw":"the disk is not encrypted","from":"Baseline v2"}]`,
			macPolicies},
	} {
		if _, err := conn.Exec(ctx, `
			INSERT INTO device_compliance
			  (tenant_id, device_id, reported_at, report, evaluated_at, state, findings, policies)
			SELECT $1, d.id, d.last_report_at, $3::jsonb, d.last_report_at, $4, $5::jsonb, $6::jsonb
			  FROM devices d WHERE d.tenant_id = $1 AND d.name = $2`,
			tenantID, v.device, v.report, v.state, v.findings, v.policies); err != nil {
			return fmt.Errorf("verdict for %s: %w", v.device, err)
		}
	}

	// Who holds what. Without this the employee page is empty for everyone
	// and the most junior surface in the product shows nothing.
	//
	// T. Eze gets two: one with things to put right and one that is fine,
	// because an employee page with a single red row does not show how it
	// reads when there is nothing to do.
	for who, devices := range map[string][]string{
		"t.eze@kalesi.example":      {"HQ-MBP-002", "Ade personal phone"},
		"o.martins@kalesi.example":  {"HQ-MBP-001"},
		"d.adeyinka@kalesi.example": {"HQ-WIN-004"},
		"p.eneh@kalesi.example":     {"FIELD-IPH-009"},
		"r.chukwu@kalesi.example":   {"HQ-MBP-OLD-7"},
	} {
		for _, name := range devices {
			if _, err := conn.Exec(ctx,
				`UPDATE devices SET assigned_to = $2 WHERE tenant_id = $1 AND name = $3`,
				tenantID, who, name); err != nil {
				return fmt.Errorf("assign %s: %w", name, err)
			}
		}
	}

	// Everything pointed at the log, so the notifications page shows a
	// configured tenant rather than an empty one.
	for _, topic := range []string{"device.lost", "approval.waiting",
		"limiter.tripped", "device.wiped", "enrolment.completed"} {
		sealedLog, err := sealer.Seal([]byte("-"))
		if err != nil {
			return err
		}
		if _, err := conn.Exec(ctx, `
			INSERT INTO notification_targets
			  (tenant_id, topic, kind, endpoint_sealed, created_by)
			VALUES ($1, $2, 'log', $3, 'o.martins')
			ON CONFLICT (tenant_id, topic) DO NOTHING`,
			tenantID, topic, sealedLog); err != nil {
			return fmt.Errorf("notification target %s: %w", topic, err)
		}
	}

	// A waiting invitation, so the enrolments page is not empty.
	if _, err := conn.Exec(ctx, `
		INSERT INTO enrolments
		  (tenant_id, token_hash, label, ownership, os_family, created_by,
		   expires_at, assigned_to)
		VALUES ($1, sha256('a-token-nobody-will-ever-redeem'::bytea),
		        'New starter laptop, Tuesday', 'company', 'macos', 'o.martins',
		        now() + interval '6 days', 'kemi.adeleke@kalesi.example')`, tenantID); err != nil {
		return err
	}

	log.Info("demonstration tenant seeded", "tenant", "Kalesi Foods", "devices", 7)
	return nil
}
