// Command tenantctl is operator-assisted onboarding: the thing that was two
// INSERT statements and a database password.
//
//	tenantctl create --name "Kalesi Foods" --slug kalesi --host mdm.kalesi.example \
//	    --issuer https://login.microsoftonline.com/<tenant>/v2.0 \
//	    --client-id <application id> --client-secret-file /root/kalesi-secret \
//	    --admin-group MDM-Owners
//	tenantctl list
//	tenantctl suspend kalesi
//	tenantctl resume kalesi
//	tenantctl add-host kalesi devices.kalesi.example
//
// IT CONNECTS AS THE OPERATOR'S ROLE, NOT AS THE DATABASE OWNER. That role
// can write the four rows a new tenant needs and cannot read a device, a
// command, an audit entry or a policy. The operator can set a tenant up and
// cannot look inside it, which is R13 made concrete: a provisioning tool run
// with the migration password would have been able to read everything.
//
// THE CLIENT SECRET NEVER REACHES THE COMMAND LINE. Same rule and same reason
// as the agent's enrolment token: ps shows every process's arguments to every
// local user. It is read from a file nobody else can read, or from standard
// input.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"platform/internal/directory"
	"platform/internal/identity"
	"platform/internal/localauth"
	"platform/internal/platformkeys"
	"platform/internal/secrets"
)

func main() {
	fail := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
		os.Exit(1)
	}
	if len(os.Args) < 2 {
		fail("usage: tenantctl create|list|suspend|resume|add-host|signups|cancel-signup|usage|billing|snapshot|set-plan|set-quota|feature|export-mode|offboard|residue|reseal-master|move-key|import ...")
	}
	cmd, args := os.Args[1], os.Args[2:]
	ctx := context.Background()

	dsn := os.Getenv("MDM_OPERATOR_DSN")
	if dsn == "" {
		fail("MDM_OPERATOR_DSN is not set. This tool connects as the operator's " +
			"role, which can set a tenant up and cannot read inside one.")
	}
	dir, err := directory.Open(ctx, dsn)
	if err != nil {
		fail("directory: %v", err)
	}
	defer dir.Close()

	switch cmd {
	case "create":
		fs := flag.NewFlagSet("create", flag.ExitOnError)
		var (
			name       = fs.String("name", "", "the organisation's name, as its staff will see it")
			slug       = fs.String("slug", "", "a short handle: lowercase letters, digits, hyphens")
			host       = fs.String("host", "", "where the console answers, e.g. mdm.kalesi.example")
			plan       = fs.String("plan", "starter", "starter, growth or scale")
			issuer     = fs.String("issuer", "", "the identity provider's issuer URL")
			clientID   = fs.String("client-id", "", "the application (client) id registered there")
			secretFile = fs.String("client-secret-file", "",
				"a file holding the client secret; without it, the secret is read from standard input")
			roleClaim  = fs.String("role-claim", "groups", "the claim carrying group membership")
			protocol   = fs.String("protocol", "oidc", "oidc, saml or local (no identity provider)")
			samlSSO    = fs.String("saml-sso-url", "", "SAML only: the provider's sign-in (SSO) URL")
			samlSLO    = fs.String("saml-slo-url", "", "SAML only: the provider's single logout URL (optional)")
			samlCert   = fs.String("saml-certificate-file", "", "SAML only: a file holding the provider's signing certificate (PEM or base64)")
			adminGroup = fs.String("admin-group", "",
				"the group whose members are the first administrators")
			ownerEmail = fs.String("owner-email", "", "local only: the first administrator's email address")
			ownerName  = fs.String("owner-name", "", "local only: the first administrator's name")
		)
		_ = fs.Parse(args)

		sealKey, _ := sealingKeys(ctx, fail)
		sealer, err := secrets.NewAESSealer(sealKey)
		if err != nil {
			fail("%v", err)
		}
		// SAML has no client secret: trust runs through the provider's
		// certificate, so nothing is read from standard input.
		var secret, certPEM string
		var inviteToken string
		var inviteHash []byte
		switch {
		case *protocol == "local":
			// No identity provider: the first administrator is an account
			// here, and gets a link that works once, for a week, to choose a
			// password. Nothing is read from standard input.
			if *ownerEmail == "" {
				fail("--protocol local needs --owner-email: the first administrator")
			}
			var terr error
			inviteToken, inviteHash, terr = localauth.NewToken()
			if terr != nil {
				fail("%v", terr)
			}
		case *protocol == "saml":
			if *samlCert == "" || *samlSSO == "" {
				fail("--protocol saml needs --saml-sso-url and --saml-certificate-file")
			}
			raw, err := os.ReadFile(*samlCert)
			if err != nil {
				fail("%v", err)
			}
			_, norm, err := identity.ParseCertificate(string(raw))
			if err != nil {
				fail("%v", err)
			}
			certPEM = norm
		default:
			var err error
			secret, err = readSecret(*secretFile, os.Stdin)
			if err != nil {
				fail("%v", err)
			}
		}
		// The tenant's own key, version 1, sealed under the master; the
		// client secret sealed under the tenant's key.
		tenantKey, err := secrets.NewTenantKey()
		if err != nil {
			fail("%v", err)
		}
		keySealed, err := sealer.Seal(tenantKey)
		if err != nil {
			fail("%v", err)
		}
		sealed, err := secrets.SealWith(tenantKey, 1, []byte(secret))
		if err != nil {
			fail("%v", err)
		}

		in := directory.NewTenant{
			Name: *name, Slug: *slug, Plan: *plan, Host: *host,
			Issuer: *issuer, ClientID: *clientID, ClientSecretSealed: sealed, KeySealed: keySealed,
			RoleClaim: *roleClaim, AdminGroup: *adminGroup,
			Protocol: *protocol, SAMLSSOURL: *samlSSO, SAMLCertificate: certPEM, SAMLSLOURL: *samlSLO,
		}
		if *protocol == "saml" || *protocol == "local" {
			in.ClientSecretSealed = nil
		}
		if *protocol == "local" {
			in.OwnerEmail, in.OwnerName, in.OwnerInviteHash = *ownerEmail, *ownerName, inviteHash
			in.OwnerCreatedBy = "tenantctl"
		}
		id, err := dir.CreateTenant(ctx, in)
		if err != nil {
			fail("not created: %v", err)
		}
		if *protocol == "local" {
			fmt.Printf(`Created %s (%s).

  Console       https://%s
  Sign-in       email and password, no identity provider
  First admin   %s

Give them this link. It works once, for seven days, and is shown only now:

  %s

They choose a password, then set up an authenticator app at first sign-in,
and add everyone else from the Users page.
`, in.Name, id, in.Host, in.OwnerEmail, in.InviteLink(inviteToken))
			return
		}
		fmt.Printf(`Created %s (%s).

  Console       https://%s
  Sign-in       %s
  First admins  members of %q at the identity provider

Register this %s at the identity provider, or sign-in will fail:

  %s

Then a member of %q signs in and finishes setup from the console.
`, in.Name, id, in.Host, in.Issuer, in.AdminGroup, registerWhat(in), in.RedirectURL(), in.AdminGroup)

	case "list":
		ts, err := dir.List(ctx)
		if err != nil {
			fail("%v", err)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "SLUG\tNAME\tPLAN\tSTATUS\tREGION\tHOSTS\tCREATED")
		for _, t := range ts {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", t.Slug, t.Name, t.Plan, t.Status, t.Region,
				strings.Join(t.Hosts, ", "), t.CreatedAt.Format("2006-01-02"))
		}
		_ = w.Flush()

	case "suspend", "resume":
		if len(args) != 1 {
			fail("usage: tenantctl %s <slug>", cmd)
		}
		status := "suspended"
		if cmd == "resume" {
			status = "active"
		}
		if err := dir.SetStatus(ctx, args[0], status); err != nil {
			fail("%v", err)
		}
		fmt.Printf("%s is now %s.\n", args[0], status)

	case "add-host":
		if len(args) != 2 {
			fail("usage: tenantctl add-host <slug> <host>")
		}
		if err := dir.AddHost(ctx, args[0], args[1]); err != nil {
			fail("%v", err)
		}
		fmt.Printf("%s now also answers on %s.\n", args[0], args[1])

	case "usage":
		// T9. Counts and bytes per tenant, from the one function the
		// operator's role may execute inside tenants. --history shows the
		// daily snapshots the sweep keeps for billing.
		fs := flag.NewFlagSet("usage", flag.ExitOnError)
		history := fs.Int("history", 0, "days of daily snapshots to show for one tenant")
		_ = fs.Parse(args)
		ts, err := dir.List(ctx)
		if err != nil {
			fail("%v", err)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "SLUG\tPLAN\tDEVICES\tCAP\tSEATS\tNEW 30D\tCOMMANDS 30D\tNOTIFICATIONS 30D\tSTORAGE")
		for _, t := range ts {
			if fs.NArg() == 1 && t.Slug != fs.Arg(0) {
				continue
			}
			u, err := dir.Usage(ctx, t.ID)
			if err != nil {
				fail("%s: %v", t.Slug, err)
			}
			fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d/%d\t%d\t%d\t%d\t%s\n", t.Slug, u.Plan, u.ActiveDevices, u.DeviceCap,
				u.SeatsUsed, u.AdminSeats, u.Enrolled30d, u.Commands30d, u.Notifications30d, humanBytes(u.StorageBytes))
			if *history > 0 && fs.NArg() == 1 {
				hs, err := dir.UsageHistory(ctx, t.ID, *history)
				if err != nil {
					fail("%v", err)
				}
				for _, h := range hs {
					fmt.Fprintf(w, "  %s\t%s\t%d\t%d\t\t\t%d\t\t%s\n", h.TakenOn.Format("2006-01-02"), h.Plan,
						h.ActiveDevices, h.DeviceCap, h.Commands30d, humanBytes(h.StorageBytes))
				}
			}
		}
		_ = w.Flush()

	case "billing":
		// T9: the month as a billing system takes it, one row per tenant,
		// from the daily snapshots. CSV by default, JSON on request.
		fs := flag.NewFlagSet("billing", flag.ExitOnError)
		month := fs.String("month", time.Now().UTC().Format("2006-01"), "the month, YYYY-MM")
		format := fs.String("format", "csv", "csv or json")
		_ = fs.Parse(args)
		from, err := time.Parse("2006-01", *month)
		if err != nil {
			fail("--month is YYYY-MM")
		}
		rowsOut, err := dir.Billing(ctx, from, from.AddDate(0, 1, 0))
		if err != nil {
			fail("%v", err)
		}
		switch *format {
		case "json":
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(map[string]any{"month": *month, "tenants": rowsOut}); err != nil {
				fail("%v", err)
			}
		case "csv":
			cw := csv.NewWriter(os.Stdout)
			_ = cw.Write([]string{"month", "tenant_id", "slug", "name", "plan", "days", "device_days", "peak_devices", "peak_storage_bytes", "commands_30d_at_end", "enrolled_30d_at_end"})
			for _, r := range rowsOut {
				_ = cw.Write([]string{*month, r.TenantID.String(), r.Slug, r.Name, r.Plan, strconv.Itoa(r.Days), strconv.Itoa(r.DeviceDays),
					strconv.Itoa(r.PeakDevices), strconv.FormatInt(r.PeakStorage, 10), strconv.Itoa(r.Commands), strconv.Itoa(r.Enrolled)})
			}
			cw.Flush()
			if err := cw.Error(); err != nil {
				fail("%v", err)
			}
		default:
			fail("--format is csv or json")
		}

	case "snapshot":
		n, err := dir.RecordUsage(ctx, time.Now())
		if err != nil {
			fail("%v", err)
		}
		fmt.Printf("%d snapshot(s) taken for today.\n", n)

	case "set-plan":
		if len(args) != 2 {
			fail("usage: tenantctl set-plan <slug> starter|growth|scale")
		}
		if err := dir.SetPlan(ctx, args[0], args[1]); err != nil {
			fail("%v", err)
		}
		fmt.Printf("%s is on the %s plan, with its numbers.\n", args[0], args[1])

	case "set-quota":
		fs := flag.NewFlagSet("set-quota", flag.ExitOnError)
		devices := fs.Int("devices", 0, "device cap")
		seats := fs.Int("seats", 0, "admin seats")
		rate := fs.Int("rate", 0, "API calls per minute")
		_ = fs.Parse(args)
		if fs.NArg() != 1 {
			fail("usage: tenantctl set-quota <slug> --devices N --seats N --rate N")
		}
		if err := dir.SetQuota(ctx, fs.Arg(0), *devices, *seats, *rate); err != nil {
			fail("%v", err)
		}
		fmt.Printf("%s: quotas updated.\n", fs.Arg(0))

	case "feature":
		if len(args) != 3 || (args[2] != "on" && args[2] != "off") {
			fail("usage: tenantctl feature <slug> <%s> on|off", strings.Join(directory.Features(), "|"))
		}
		if err := dir.SetFeature(ctx, args[0], args[1], args[2] == "on"); err != nil {
			fail("%v", err)
		}
		fmt.Printf("%s: %s is %s.\n", args[0], args[1], args[2])

	case "export-mode":
		// T10 step two: the tenant stops running and its Super Admin can
		// still download the export.
		if len(args) != 1 {
			fail("usage: tenantctl export-mode <slug>")
		}
		if err := dir.SetStatus(ctx, args[0], "exporting"); err != nil {
			fail("%v", err)
		}
		fmt.Printf("%s is exporting: its console answers only the export download until it is resumed or offboarded.\n", args[0])

	case "offboard":
		// T10 step three. Every row, every key, counted, verified, logged.
		fs := flag.NewFlagSet("offboard", flag.ExitOnError)
		confirm := fs.String("confirm", "", "type the slug again")
		_ = fs.Parse(args)
		if fs.NArg() != 1 || *confirm != fs.Arg(0) {
			fail("usage: tenantctl offboard <slug> --confirm <slug>   (the tenant must be suspended or exporting)")
		}
		out, err := dir.Offboard(ctx, fs.Arg(0), os.Getenv("USER"))
		if err != nil {
			fail("%v", err)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "TABLE\tDELETED")
		for _, tbl := range sortedKeys(out.Deleted) {
			fmt.Fprintf(w, "%s\t%d\n", tbl, out.Deleted[tbl])
		}
		_ = w.Flush()
		fmt.Printf("\n%s offboarded: %d rows deleted, %d remaining (verified). Keys destroyed with their tables: tenant_ca, tenant_identity, sending_domains, notification_targets.\n",
			out.Slug, out.Total(), out.Residue)

	case "residue":
		if len(args) != 1 {
			fail("usage: tenantctl residue <slug>")
		}
		ts, err := dir.List(ctx)
		if err != nil {
			fail("%v", err)
		}
		for _, t := range ts {
			if t.Slug != args[0] {
				continue
			}
			res, err := dir.Residue(ctx, t.ID)
			if err != nil {
				fail("%v", err)
			}
			var total int64
			for _, tbl := range sortedKeys(res) {
				fmt.Printf("%-28s %d\n", tbl, res[tbl])
				total += res[tbl]
			}
			fmt.Printf("total %d\n", total)
		}

	case "partner":
		// T7. partner create|list|rotate-token; set-partner moves a tenant.
		if len(args) < 1 {
			fail("usage: tenantctl partner create|list|rotate-token ...")
		}
		switch args[0] {
		case "create":
			fs := flag.NewFlagSet("partner create", flag.ExitOnError)
			name := fs.String("name", "", "the partner's name")
			slug := fs.String("slug", "", "a short handle")
			product := fs.String("product-name", "", "the brand its tenants start with")
			colour := fs.String("colour", "", "the brand colour its tenants start with")
			footer := fs.String("footer", "", "the legal footer its tenants start with")
			capN := fs.Int("tenants", 25, "how many tenants it may have")
			_ = fs.Parse(args[1:])
			p, token, err := dir.CreatePartner(ctx, *slug, *name, *product, *colour, *footer, *capN)
			if err != nil {
				fail("%v", err)
			}
			fmt.Printf("Partner %s (%s) created, up to %d tenants.\n\nToken, shown once:\n\n  %s\n\nIt is sent as Authorization: Bearer to /partner/... on the sign-up host.\n", p.Name, p.Slug, p.TenantCap, token)
		case "list":
			ps, err := dir.ListPartners(ctx)
			if err != nil {
				fail("%v", err)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "SLUG\tNAME\tTENANTS\tCAP\tBRAND\tLAST USED")
			for _, p := range ps {
				last := "never"
				if p.LastUsedAt != nil {
					last = p.LastUsedAt.Format("2006-01-02 15:04")
				}
				fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\t%s\n", p.Slug, p.Name, p.Tenants, p.TenantCap, p.ProductName, last)
			}
			_ = w.Flush()
		case "rotate-token":
			if len(args) != 2 {
				fail("usage: tenantctl partner rotate-token <slug>")
			}
			token, err := dir.RotatePartnerToken(ctx, args[1])
			if err != nil {
				fail("%v", err)
			}
			fmt.Printf("New token for %s, shown once; the old one no longer works:\n\n  %s\n", args[1], token)
		default:
			fail("usage: tenantctl partner create|list|rotate-token ...")
		}

	case "set-partner":
		if len(args) != 2 {
			fail("usage: tenantctl set-partner <tenant slug> <partner slug>")
		}
		if err := dir.AssignPartner(ctx, args[0], args[1]); err != nil {
			fail("%v", err)
		}
		fmt.Printf("%s is now managed by %s.\n", args[0], args[1])

	case "reseal-master":
		// T3. Rotating the master key, step two of three. Step one is a
		// deployment with the new key as MDM_SEALING_KEY and the old one
		// as MDM_SEALING_KEY_PREVIOUS, which keeps every tenant key
		// readable meanwhile. This moves every tenant key under the new
		// master, all or nothing. Step three removes the previous key
		// from the deployment, once --verify says nothing still needs it.
		fs := flag.NewFlagSet("reseal-master", flag.ExitOnError)
		dry := fs.Bool("dry-run", false, "say what would move and change nothing")
		verify := fs.Bool("verify", false, "only check that every key opens under the current master")
		_ = fs.Parse(args)
		curKey, prevKey := sealingKeys(ctx, fail)
		cur, err := secrets.NewAESSealer(curKey)
		if err != nil {
			fail("sealing_key: %v", err)
		}
		if *verify {
			total, failing, err := dir.VerifyMasterKeys(ctx, func(b []byte) error { _, err := cur.Open(b); return err })
			if err != nil {
				fail("%v", err)
			}
			fmt.Printf("tenant keys: %d\nopen under the current master: %d\nstill under another master: %d\n",
				total, total-len(failing), len(failing))
			for _, f := range failing {
				fmt.Println("  ", f)
			}
			if len(failing) > 0 {
				fail("keep MDM_SEALING_KEY_PREVIOUS in the deployment and run reseal-master")
			}
			return
		}
		if prevKey == nil {
			fail("sealing_key_previous (the master being rotated out) is not set: MDM_SEALING_KEY_PREVIOUS, or the field in the key directory or vault")
		}
		prev, err := secrets.NewAESSealer(prevKey)
		if err != nil {
			fail("sealing_key_previous: %v", err)
		}
		if *dry {
			blobs, err := dir.KeyBlobs(ctx)
			if err != nil {
				fail("%v", err)
			}
			var would, already, unexplained int
			for _, b := range blobs {
				_, al, err := secrets.ResealMaster(prev, cur, b.Sealed)
				switch {
				case err != nil:
					unexplained++
					fmt.Printf("  would halt on tenant %s version %d: %v\n", b.TenantID, b.Version, err)
				case al:
					already++
				default:
					would++
				}
			}
			fmt.Printf("tenant keys: %d\nwould move: %d\nalready current: %d\nunexplained: %d\n",
				len(blobs), would, already, unexplained)
			return
		}
		rep, err := dir.ResealMasterKeys(ctx, func(b []byte) ([]byte, bool, error) { return secrets.ResealMaster(prev, cur, b) })
		if err != nil {
			fail("halted: %v", err)
		}
		// The in-vs-out block. Everything read is accounted for in one of
		// two buckets; there is no third, because a third halts the run.
		fmt.Printf("tenant keys read: %d\nmoved to the new master: %d\nalready under it: %d\nunexplained: 0\n",
			rep.Total, rep.Resealed, rep.AlreadyCurrent)
		fmt.Println("next: run reseal-master --verify, then remove MDM_SEALING_KEY_PREVIOUS from the deployment")

	case "move-key":
		// T11, step one, on the DESTINATION: a transport key to hand to
		// the tenant's Super Admin out of band. They make the move bundle
		// with it on the source's Sign-in page; this region imports with it.
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			fail("%v", err)
		}
		fmt.Println(base64.StdEncoding.EncodeToString(k))
		fmt.Fprintln(os.Stderr, "give this to the tenant's Super Admin for the move bundle; keep it for tenantctl import; it is not stored anywhere")

	case "import":
		// T11, step two, on the destination: the bundle lands whole or not
		// at all, suspended, under this region's master key.
		fs := flag.NewFlagSet("import", flag.ExitOnError)
		tkey := fs.String("transport-key", "", "the key tenantctl move-key printed")
		region := fs.String("region", os.Getenv("MDM_REGION"), "this region (defaults to MDM_REGION)")
		_ = fs.Parse(args)
		if fs.NArg() != 1 || *tkey == "" {
			fail("usage: tenantctl import <bundle.zip> --transport-key <key> [--region <region>]")
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(*tkey))
		if err != nil || len(raw) != 32 {
			fail("--transport-key is the base64 of the 32-byte key tenantctl move-key printed")
		}
		transport, err := secrets.NewAESSealer(raw)
		if err != nil {
			fail("%v", err)
		}
		masterKey, _ := sealingKeys(ctx, fail)
		master, err := secrets.NewAESSealer(masterKey)
		if err != nil {
			fail("sealing_key: %v", err)
		}
		bundle, err := os.ReadFile(fs.Arg(0))
		if err != nil {
			fail("%v", err)
		}
		rep, err := dir.ImportTenant(ctx, bundle, directory.ImportInput{
			Transport: transport, Master: master, Region: *region, By: os.Getenv("USER")})
		if err != nil {
			fail("halted: %v", err)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "TABLE\tSENT\tLANDED")
		names := make([]string, 0, len(rep.Sent))
		for tbl := range rep.Sent {
			names = append(names, tbl)
		}
		sort.Strings(names)
		for _, tbl := range names {
			fmt.Fprintf(w, "%s\t%d\t%d\n", tbl, rep.Sent[tbl], rep.Landed[tbl])
		}
		_ = w.Flush()
		fmt.Printf("\n%s imported from %s into %s, suspended; unexplained: 0.\n", rep.Slug, rep.FromRegion, *region)
		fmt.Println("next: point the tenant's hostnames at this region, tenantctl resume " + rep.Slug + ", then offboard it at the source")

	case "signups":
		// The operator's view of self-service sign-ups. Open ones by
		// default, which is the question "where is the one from this
		// morning"; --all for the record.
		fs := flag.NewFlagSet("signups", flag.ExitOnError)
		all := fs.Bool("all", false, "include finished, expired and replaced sign-ups")
		_ = fs.Parse(args)
		rs, err := dir.ListSignups(ctx, *all)
		if err != nil {
			fail("%v", err)
		}
		if len(rs) == 0 {
			if *all {
				fmt.Println("No sign-ups.")
			} else {
				fmt.Println("No open sign-ups. --all shows finished and expired ones.")
			}
			return
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "STATE\tEMAIL\tCOMPANY\tSLUG\tFROM\tREQUESTED\tEXPIRES\tTENANT")
		for _, r := range rs {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.State, r.Email, r.Company,
				r.Slug, r.RequestedIP, r.RequestedAt.Local().Format("2006-01-02 15:04"),
				r.ExpiresAt.Local().Format("2006-01-02 15:04"), r.TenantSlug)
		}
		_ = w.Flush()
		fmt.Println("\nStates: waiting (link sent), opened (address proven), finished, expired, replaced (asked again).")

	case "cancel-signup":
		if len(args) != 1 {
			fail("usage: tenantctl cancel-signup <email>")
		}
		if err := dir.CancelSignup(ctx, args[0]); err != nil {
			fail("%v", err)
		}
		fmt.Printf("The open sign-up link for %s no longer works.\n", args[0])

	default:
		fail("unknown command %q: use create, list, suspend, resume, add-host, signups, cancel-signup, usage, snapshot, set-plan, set-quota or feature", cmd)
	}
}

// readSecret is the same rule the agent applies to its enrolment token, for
// the same reason. Duplicated rather than shared because the agent is built
// for five platforms with no dependency on the server tree, and this is the
// only other place the rule is needed.
func readSecret(path string, stdin io.Reader) (string, error) {
	if path == "" {
		if f, ok := stdin.(*os.File); ok {
			if info, err := f.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
				fmt.Fprint(os.Stderr, "client secret: ")
			}
		}
		line, err := bufio.NewReader(stdin).ReadString('\n')
		s := strings.TrimSpace(line)
		if s == "" {
			if err != nil && !errors.Is(err, io.EOF) {
				return "", err
			}
			return "", errors.New("no client secret was given")
		}
		return s, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf("%s is readable by other users (mode %04o); chmod 600 it, "+
			"or pipe the secret in on standard input", path, perm)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return s, nil
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func sortedKeys(m map[string]int64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// registerWhat names the thing the provider has to know about us.
func registerWhat(in directory.NewTenant) string {
	if in.Protocol == "saml" {
		return "reply URL (and our entity id " + in.EntityID() + ", or our metadata there)"
	}
	return "redirect URL"
}

// sealingKeys reads the sealing master, and the one being rotated out if
// any, from the same source the gateway uses (MDM_KEY_SOURCE): a key
// directory, a vault, or the environment. The signing keys are not needed
// here and are not asked for.
func sealingKeys(ctx context.Context, fail func(string, ...any)) (current, previous []byte) {
	src, err := platformkeys.Choose(os.Getenv)
	if err != nil {
		fail("%v", err)
	}
	current, previous, err = platformkeys.LoadSealing(ctx, src)
	if err != nil {
		fail("%v. The client secrets are sealed with the same key the gateway runs with, or the gateway cannot open them.", err)
	}
	return current, previous
}
