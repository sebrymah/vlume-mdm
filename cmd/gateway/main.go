// Command gateway runs the front door.
//
// It is runnable today against the schema in db/migrations and will complete
// a real sign-in against a real Microsoft Entra ID or Google Workspace tenant
// once that tenant's row exists in tenant_identity. See the README for the
// two statements that put one there.
//
// What it still cannot do is talk to a device, because that needs the Apple
// MDM vendor certificate. The seam is command.PushProvider and the build is
// written so that nothing else waits on it.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"platform/internal/android"
	"platform/internal/authz"
	"platform/internal/branding"
	"platform/internal/command"
	"platform/internal/data"
	"platform/internal/directory"
	"platform/internal/enrol"
	"platform/internal/gateway"
	"platform/internal/identity"
	"platform/internal/notify"
	"platform/internal/platformkeys"
	"platform/internal/secrets"
	"platform/internal/session"
	"platform/internal/tenantclaim"
)

// devVerifier reads a fixed map of bearer token to identity from a file.
//
// It is no longer the identity provider: that is internal/identity, speaking
// OpenID Connect to each tenant's own. What this is for now is calling the
// API from a terminal without going through a browser sign-in, and it still
// refuses to load unless the operator has said so out loud.
type devVerifier map[string]gateway.Identity

func (d devVerifier) Verify(_ context.Context, bearer string) (gateway.Identity, error) {
	id, ok := d[bearer]
	if !ok {
		return gateway.Identity{}, gateway.ErrNoIdentity
	}
	return id, nil
}

type devEntry struct {
	Subject  string `json:"subject"`
	TenantID string `json:"tenant_id"`
	Role     string `json:"role"`
}

func loadDevVerifier(path string, log *slog.Logger) (gateway.IdentityVerifier, error) {
	if os.Getenv("MDM_ALLOW_DEV_IDENTITIES") != "yes" {
		return nil, errors.New(
			"the development identity file needs MDM_ALLOW_DEV_IDENTITIES=yes set deliberately")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]devEntry
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	out := devVerifier{}
	for token, e := range raw {
		tid, err := uuid.Parse(e.TenantID)
		if err != nil {
			return nil, err
		}
		role, err := authz.Parse(e.Role)
		if err != nil {
			return nil, err
		}
		out[token] = gateway.Identity{Subject: e.Subject, TenantID: tid, Role: role}
	}
	log.Warn("DEVELOPMENT IDENTITIES IN USE",
		"file", path, "identities", len(out),
		"note", "these are not an identity provider and must not reach any deployment")
	return out, nil
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctx := context.Background()

	fail := func(msg string, args ...any) {
		log.Error(msg, args...)
		os.Exit(1)
	}
	must := func(name string) string {
		v := os.Getenv(name)
		if v == "" {
			fail("missing environment variable", "name", name)
		}
		return v
	}

	// Three keys, three jobs, deliberately not one key doing all three.
	// They come from the source MDM_KEY_SOURCE names: a key directory, a
	// vault, or the environment, which is for a laptop and is warned
	// about. Whatever the source, they are checked the same way before
	// anything runs, and the bytes are never logged: the start-up line is
	// where they came from and a fingerprint of each.
	//
	//   claim   signs the short internal tenant claim
	//   session signs the console's sign-in cookies
	//   sealing encrypts stored identity provider client secrets
	keySource, err := platformkeys.Choose(os.Getenv)
	if err != nil {
		fail("platform keys", "err", err)
	}
	keys, err := platformkeys.Load(ctx, keySource)
	if err != nil {
		fail("platform keys", "err", err)
	}
	log.Info("platform keys", "keys", keys.Describe())
	if _, fromEnv := keySource.(platformkeys.Env); fromEnv {
		log.Warn("the platform keys come from the environment; a deployment takes them from a key directory or a vault",
			"set", "MDM_KEY_SOURCE=files or MDM_KEY_SOURCE=vault")
	}
	signer, err := tenantclaim.NewSigner(keys.Claim)
	if err != nil {
		fail("claim signing key rejected", "err", err)
	}
	sessions, err := session.NewSigner(keys.Session)
	if err != nil {
		fail("session signing key rejected", "err", err)
	}
	master, err := secrets.NewAESSealer(keys.Sealing)
	if err != nil {
		fail("sealing key rejected", "err", err)
	}
	// The master seals tenant keys and nothing else; everything a tenant
	// has is sealed under its own key (T3). A master being rotated out is
	// named as well, for the window until tenantctl reseal-master has run.
	var previous []*secrets.AESSealer
	if keys.SealingPrevious != nil {
		p, err := secrets.NewAESSealer(keys.SealingPrevious)
		if err != nil {
			fail("previous sealing key rejected", "err", err)
		}
		previous = append(previous, p)
		log.Warn("a previous sealing key is configured; run tenantctl reseal-master, then remove it")
	}
	sealer := secrets.NewKeyring(master, previous...)
	// Re-read while running (0044): every five minutes and on SIGHUP, a
	// changed set is handed to the signers and the keyring, each keeping
	// the key before it for what it signed or sealed. The environment
	// cannot change under a running process, so it is not watched.
	rotate := func(gw *gateway.Gateway) func(platformkeys.Keys) error {
		return func(k platformkeys.Keys) error {
			if err := signer.Rotate(k.Claim); err != nil {
				return err
			}
			if err := sessions.Rotate(k.Session); err != nil {
				return err
			}
			m, err := secrets.NewAESSealer(k.Sealing)
			if err != nil {
				return err
			}
			sealer.RotateMaster(m)
			gw.RotateCSRFKey(k.Claim)
			return nil
		}
	}

	store, err := data.Open(ctx, must("MDM_APP_DSN"), signer, 16)
	if err != nil {
		fail("database", "err", err)
	}
	defer store.Close()

	dir, err := directory.Open(ctx, must("MDM_OPERATOR_DSN"))
	if err != nil {
		fail("directory", "err", err)
	}
	defer dir.Close()

	// The bearer-token stand-in is optional now. A deployment that only has
	// browser sign-in leaves MDM_DEV_IDENTITIES unset and gets nil, which
	// the gateway reads as "no other credential kind is accepted".
	var idp gateway.IdentityVerifier
	if path := os.Getenv("MDM_DEV_IDENTITIES"); path != "" {
		idp, err = loadDevVerifier(path, log)
		if err != nil {
			fail("development identities", "err", err)
		}
	}

	insecure := os.Getenv("MDM_INSECURE_COOKIES") == "yes"
	if insecure {
		log.Warn("INSECURE COOKIES",
			"note", "session cookies are being sent without the Secure attribute, "+
				"which means they travel over plain HTTP. Development only.")
	}

	addr := os.Getenv("MDM_LISTEN")
	if addr == "" {
		addr = ":8080"
	}

	// Notifications. The webhook channel refuses addresses inside this
	// platform's own network, because the endpoint is supplied by a tenant
	// administrator and the request is made from in here.
	syslogCh := notify.NewSyslog()
	syslogCh.AllowPrivateAddresses = os.Getenv("MDM_SIEM_ALLOW_PRIVATE") == "yes"
	jira := notify.NewTicketing("jira", log)
	snow := notify.NewTicketing("servicenow", log)
	channels := []notify.Channel{notify.NewWebhook(log), notify.NewLog(log), syslogCh, jira, snow}
	// Email only exists if a mail server does. A deployment without one
	// refuses an email target by name rather than accepting it and
	// silently delivering nothing.
	if server := os.Getenv("MDM_SMTP_SERVER"); server != "" {
		mail := notify.Email{
			Server: server,
			From:   os.Getenv("MDM_SMTP_FROM"),
			// Operator configuration, never a tenant's: what a tenant sets
			// is WHO is written to, not how mail leaves.
			Username: os.Getenv("MDM_SMTP_USERNAME"),
			Password: os.Getenv("MDM_SMTP_PASSWORD"),
			Security: os.Getenv("MDM_SMTP_SECURITY"),
			Helo:     os.Getenv("MDM_SMTP_HELO"),
		}
		if mail.Security == "" {
			mail.Security = "starttls"
		}
		if mail.From == "" {
			fail("MDM_SMTP_SERVER is set but MDM_SMTP_FROM is not", nil)
		}
		channels = append(channels, mail)
		log.Info("email notifications enabled", "server", server,
			"security", mail.Security, "authenticated", mail.Username != "")
	} else {
		log.Warn("email notifications are not available",
			"note", "set MDM_SMTP_SERVER and MDM_SMTP_FROM to enable them")
	}
	notifier := notify.New(sealer, channels...)
	go notify.NewWorker(notifier, store, signer, dir.ActiveTenantIDs, log).Run(ctx)

	// Self-service sign-up. Off unless a hostname is given for it, and then
	// it needs a mail server, because a sign-up that cannot send its
	// verification link is a page that creates nothing and says so late.
	// The channel that carries mail to a person (an enrolment invitation):
	// the email channel when there is one, otherwise nothing, and the
	// console then shows the link to be passed on by hand.
	var mailChannel notify.Channel
	for _, ch := range channels {
		if ch.Name() == "email" {
			mailChannel = ch
		}
	}

	// The platform owner's console: one hostname, off unless it is named.
	var operatorCfg *gateway.OperatorConfig
	if host := os.Getenv("MDM_OPERATOR_HOST"); host != "" {
		operatorCfg = &gateway.OperatorConfig{Host: host}
	}

	var signup *gateway.SignupConfig
	if host := os.Getenv("MDM_SIGNUP_HOST"); host != "" {
		domain := must("MDM_SIGNUP_TENANT_DOMAIN")
		var mailer notify.Channel
		for _, ch := range channels {
			if ch.Name() == "email" {
				mailer = ch
			}
		}
		if mailer == nil {
			fail("MDM_SIGNUP_HOST is set but there is no mail server (MDM_SMTP_SERVER)", nil)
		}
		if from := os.Getenv("MDM_SIGNUP_FROM"); from != "" {
			m := mailer.(notify.Email)
			m.From = from
			mailer = m
		}
		brand := branding.Brand{
			ProductName: os.Getenv("MDM_SIGNUP_PRODUCT_NAME"),
			Colour:      os.Getenv("MDM_SIGNUP_COLOUR"),
			LegalFooter: os.Getenv("MDM_SIGNUP_FOOTER"),
		}
		if brand.Colour != "" {
			if err := branding.Validate(brand.Colour); err != nil {
				fail("MDM_SIGNUP_COLOUR", "err", err)
			}
		}
		signup = &gateway.SignupConfig{Host: host, TenantDomain: domain, Brand: brand, Mail: mailer}
		for _, rg := range strings.Split(os.Getenv("MDM_SIGNUP_REGIONS"), ",") {
			if rg = strings.TrimSpace(rg); rg != "" {
				signup.Regions = append(signup.Regions, rg)
			}
		}
		log.Info("self-service sign-up enabled", "host", host, "tenant_domain", domain)
	}

	// Behind a load balancer, which peers may say who the caller is.
	// Nothing by default: a header believed from everyone is an address
	// the stranger chooses.
	// A deployment's own sign-up refusals, on top of the shipped list of
	// providers anyone can get an address at.
	if path := os.Getenv("MDM_SIGNUP_BLOCKED_DOMAINS_FILE"); path != "" {
		n, err := directory.LoadBlockedDomainsFile(path)
		if err != nil {
			fail("MDM_SIGNUP_BLOCKED_DOMAINS_FILE", "err", err)
		}
		log.Info("sign-up refusals", "shipped", directory.FreeMailCount(), "added", n)
	}

	proxies, err := gateway.ParseTrustedProxies(os.Getenv("MDM_TRUSTED_PROXIES"))
	if err != nil {
		fail("MDM_TRUSTED_PROXIES", "err", err)
	}
	if len(proxies) > 0 {
		log.Info("trusting X-Forwarded-For from", "proxies", proxies)
	}

	// Android Enterprise. One service account for the platform, held by
	// the operator. Without it every Android page says what is missing.
	var androidAPI android.Provider = android.NotConfigured{}
	if path := os.Getenv("MDM_ANDROID_CREDENTIALS_FILE"); path != "" {
		creds, err := os.ReadFile(path)
		if err != nil {
			fail("MDM_ANDROID_CREDENTIALS_FILE", "err", err)
		}
		client, err := android.NewAMAPI(ctx, creds)
		if err != nil {
			fail("android credentials", "err", err)
		}
		androidAPI = client
		log.Info("Android Enterprise enabled")
	} else {
		log.Warn("Android Enterprise is not available",
			"note", "set MDM_ANDROID_CREDENTIALS_FILE to a service account for the Android Management API")
	}

	gw := gateway.New(gateway.Config{
		TrustedProxies: proxies,
		Region:         os.Getenv("MDM_REGION"),
		Directory:      dir, Store: store, Signer: signer, Identity: idp,
		Sessions: sessions, OIDC: identity.NewOIDC(), SAML: identity.NewSAML(), Sealer: sealer,
		Enrol:           enrol.New(sealer),
		Notify:          notifier,
		Mail:            mailChannel,
		InsecureCookies: insecure,
		Android:         androidAPI,
		// Command signing keys are rows: a key per tenant and version,
		// sealed under the tenant's own key, rotated from the console.
		//
		// Commands route by operating system: Android goes to Google,
		// everything else still waits on the Apple vendor certificate.
		Pipeline: command.New(&command.StoredKeys{Sealer: sealer},
			command.ByOS{
				Routes:   map[string]command.PushProvider{"android": android.Push{Provider: androidAPI}},
				Fallback: command.AppleNotConfigured(),
			}, command.DefaultLimiter()),
		CSRFKey: keys.Claim, Log: log,
		Signup: signup, Operator: operatorCfg,
	})
	// F8's fifteen minutes, for the devices Google reports on.
	go gw.RunAndroidSync(ctx, dir.ActiveTenantIDs, 15*time.Minute)

	// Daily. The window it warns inside is measured in weeks, so anything
	// more often would be a notification system testing its own
	// deduplication.
	go gw.RunWake(ctx)
	go gw.RunExpirySweep(ctx, dir.ActiveTenantIDs, 24*time.Hour)
	go gw.RunWeeklyReport(ctx, dir.ActiveTenantIDs, dir.PrimaryHost, 24*time.Hour)
	go gateway.RunUsageSnapshots(ctx, dir.RecordUsage, 6*time.Hour, log)
	go gw.RunComplianceSnapshots(ctx, dir.ActiveTenantIDs, 24*time.Hour)
	if _, fromEnv := keySource.(platformkeys.Env); !fromEnv {
		reload := make(chan struct{}, 1)
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		go func() {
			for range hup {
				select {
				case reload <- struct{}{}:
				default:
				}
			}
		}()
		go platformkeys.Watch(ctx, keySource, 5*time.Minute, reload, keys, rotate(gw), log)
		log.Info("platform keys are re-read every five minutes and on SIGHUP")
	}
	go gw.RunSIEMExport(ctx, dir.ActiveTenantIDs, dir.SlugOf, time.Minute)

	srv := &http.Server{
		Addr:              addr,
		Handler:           gw.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// T5: managed TLS. With MDM_TLS=managed the gateway answers on :443
	// with certificates from an ACME authority for every verified tenant
	// hostname, and on :80 only to redirect and to answer challenges. The
	// host policy is the directory: a hostname that is not a tenant's gets
	// no certificate and no connection. The cache is the operator's table,
	// so every instance shares one set of certificates and one account.
	if os.Getenv("MDM_TLS") == "managed" {
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: dir.HostAllowed,
			Cache:      dir.CertCache(),
			Email:      os.Getenv("MDM_TLS_EMAIL"),
		}
		if dirURL := os.Getenv("MDM_TLS_DIRECTORY"); dirURL != "" {
			// A private or staging ACME directory, for anything that is
			// not Let's Encrypt's production endpoint.
			m.Client = &acme.Client{DirectoryURL: dirURL}
		}
		srv.Addr = ":443"
		srv.TLSConfig = m.TLSConfig()
		go func() {
			plain := &http.Server{Addr: ":80", Handler: m.HTTPHandler(nil), ReadHeaderTimeout: 10 * time.Second}
			if err := plain.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("port 80", "err", err)
			}
		}()
		log.Info("gateway listening with managed TLS", "addr", srv.Addr, "email", m.Email)
		if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fail("server", "err", err)
		}
		return
	}

	log.Info("gateway listening", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fail("server", "err", err)
	}
}
