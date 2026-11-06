// devreport stands in for a device in the local demonstration.
//
// The demonstration runs over plain HTTP, and a real report arrives on a
// device certificate over TLS, so no device can report to it. This tool
// runs the same evaluation the gateway would, through the same policy.Apply,
// under a claim for the demonstration tenant. It exists for the demo and
// for nothing else: it needs the database password and the claim key, which
// no device has.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"

	"platform/internal/authz"
	"platform/internal/data"
	"platform/internal/policy"
	"platform/internal/tenantclaim"
)

func main() {
	serial := flag.String("serial", "", "the device's serial, as the console shows it")
	report := flag.String("report", "", `the report as JSON, e.g. {"passcode_set": false, "disk_encryption": true}`)
	policyBody := flag.String("policy", "", `save this JSON as a new version of the "Baseline" policy first`)
	tenant := flag.String("tenant", "11111111-1111-1111-1111-111111111111", "tenant id")
	flag.Parse()

	fail := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
		os.Exit(1)
	}
	dsn, key := os.Getenv("MDM_APP_DSN"), os.Getenv("MDM_CLAIM_SIGNING_KEY")
	if dsn == "" || key == "" {
		fail("MDM_APP_DSN and MDM_CLAIM_SIGNING_KEY are needed")
	}
	tenantID, err := uuid.Parse(*tenant)
	if err != nil {
		fail("tenant: %v", err)
	}
	ctx := context.Background()
	signer, err := tenantclaim.NewSigner([]byte(key))
	if err != nil {
		fail("signer: %v", err)
	}
	store, err := data.Open(ctx, dsn, signer, 2)
	if err != nil {
		fail("database: %v", err)
	}
	defer store.Close()
	claim, err := signer.Mint(tenantclaim.Claim{
		TenantID: tenantID, Subject: "devreport", Role: string(authz.ITAdmin),
		RequestID: uuid.NewString(),
	}, time.Minute)
	if err != nil {
		fail("claim: %v", err)
	}

	err = store.WithTenant(ctx, claim, func(ctx context.Context, tx *data.Tx) error {
		if *policyBody != "" {
			p, err := policy.Save(ctx, tx, policy.SaveInput{
				Name: "Baseline", Body: []byte(*policyBody), CreatedBy: "devreport",
			})
			if err != nil {
				return err
			}
			fmt.Printf("policy saved: %s (on failure: %s)\n", p.Label(), p.OnFailure)
		}
		if *serial == "" {
			return nil
		}
		var deviceID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT id FROM devices WHERE serial = $1`, *serial).Scan(&deviceID); err != nil {
			return fmt.Errorf("no device with serial %s: %w", *serial, err)
		}
		var rep policy.Report
		if err := json.Unmarshal([]byte(*report), &rep); err != nil {
			return fmt.Errorf("report: %w", err)
		}
		out, err := policy.Apply(ctx, tx, deviceID, rep, time.Now().UTC())
		if err != nil {
			return err
		}
		fmt.Printf("verdict: %s\n", out.State)
		for _, f := range out.Findings {
			fmt.Printf("  finding: %s (saw %s) from %s\n", f.Rule, f.Saw, f.From)
		}
		fmt.Printf("device state: %s\n", out.DeviceState)
		if out.Enforcement != "" {
			fmt.Printf("enforcement: %s\n", out.Enforcement)
		}
		return nil
	})
	if err != nil {
		fail("%v", err)
	}
}
