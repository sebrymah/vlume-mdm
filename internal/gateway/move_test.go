package gateway

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"platform/internal/data"
	"platform/internal/directory"
	"platform/internal/secrets"
	"platform/internal/tenantclaim"
)

// T11: moving a tenant to another region. The bundle carries sealed values
// and the tenant's keys under a transport key; the import lands it whole
// or not at all; afterwards the tenant works, with its secrets, on the
// other side.

func transportKey(t *testing.T) (string, *secrets.AESSealer) {
	t.Helper()
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	s, err := secrets.NewAESSealer(k)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k), s
}

// sealForTenant seals a value under tenant A's own key, as the console does.
func sealForTenant(t *testing.T, f fixture, plain string) []byte {
	t.Helper()
	claim, err := f.g.signer.Mint(tenantclaim.Claim{TenantID: tenantA, Subject: "test", Role: "super_admin", RequestID: uuid.NewString()}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var sealed []byte
	if err := f.g.store.WithTenant(context.Background(), claim, func(ctx context.Context, tx *data.Tx) error {
		var e error
		sealed, e = f.sealer.Seal(ctx, tx, []byte(plain))
		return e
	}); err != nil {
		t.Fatal(err)
	}
	return sealed
}

func unzipAll(t *testing.T, b []byte) map[string]string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("zip: %v", err)
	}
	files := map[string]string{}
	for _, zf := range zr.File {
		rc, _ := zf.Open()
		c, _ := io.ReadAll(rc)
		rc.Close()
		files[zf.Name] = string(c)
	}
	return files
}

func rezip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, c := range files {
		w, _ := zw.Create(name)
		_, _ = w.Write([]byte(c))
	}
	_ = zw.Close()
	return buf.Bytes()
}

func moveBundleOf(t *testing.T, f fixture, key string) []byte {
	t.Helper()
	rec := raw(t, f, jsonReq(t, "POST", hostA, "/api/export/move", "a-super", map[string]any{"transport_key": key}))
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("move bundle: %d %s", rec.Code, rec.Body.String())
	}
	return rec.Body.Bytes()
}

func TestAMoveBundleCarriesSealedValuesUnderTheTransportKey(t *testing.T) {
	f := newFixture(t)
	baseline(t, f)
	sealed := sealForTenant(t, f, "the-client-secret")
	exec(t, `INSERT INTO tenant_identity (tenant_id, issuer, client_id, client_secret_sealed, redirect_url)
	         VALUES ($1, 'https://login.example/v2.0', 'c', $2, 'https://x/signin/callback')`, tenantA, sealed)

	// Only a Super Admin, only with a real key.
	if rec := raw(t, f, jsonReq(t, "POST", hostA, "/api/export/move", "a-itadmin", map[string]any{"transport_key": "x"})); rec.Code != http.StatusForbidden {
		t.Fatalf("an IT admin made a move bundle: %d", rec.Code)
	}
	if rec := raw(t, f, jsonReq(t, "POST", hostA, "/api/export/move", "a-super", map[string]any{"transport_key": "dG9vc2hvcnQ="})); rec.Code != http.StatusBadRequest {
		t.Fatalf("a short key was accepted: %d", rec.Code)
	}

	key, transport := transportKey(t)
	files := unzipAll(t, moveBundleOf(t, f, key))
	if strings.Contains(files["tenant_identity.jsonl"], "[not exported]") {
		t.Fatal("the move bundle redacted the sealed secret; it is an export, not a move")
	}
	// The tenant key opens under the transport key, and with it the secret.
	var keyRow map[string]any
	if err := json.Unmarshal([]byte(strings.SplitN(files["tenant_keys.jsonl"], "\n", 2)[0]), &keyRow); err != nil {
		t.Fatalf("tenant_keys.jsonl: %v", err)
	}
	under, _ := hex.DecodeString(strings.TrimPrefix(keyRow["key_sealed"].(string), "\\x"))
	tenantKey, err := transport.Open(under)
	if err != nil {
		t.Fatalf("the tenant key does not open under the transport key: %v", err)
	}
	var idRow map[string]any
	_ = json.Unmarshal([]byte(strings.SplitN(files["tenant_identity.jsonl"], "\n", 2)[0]), &idRow)
	secretSealed, _ := hex.DecodeString(strings.TrimPrefix(idRow["client_secret_sealed"].(string), "\\x"))
	if plain, err := secrets.OpenWith(tenantKey, secretSealed); err != nil || string(plain) != "the-client-secret" {
		t.Fatalf("the sealed secret does not open with the moved tenant key: %v %q", err, plain)
	}
	if !strings.Contains(files["manifest.json"], `"move": true`) || !strings.Contains(files["manifest.json"], `"slug": "kalesi"`) {
		t.Fatalf("manifest: %s", files["manifest.json"])
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'tenant.move_exported'`, tenantA); n != 1 {
		t.Fatal("the move export was not audited")
	}
}

func TestAMovedTenantArrivesWholeAndWorks(t *testing.T) {
	f := newFixture(t)
	baseline(t, f)
	sealed := sealForTenant(t, f, "the-client-secret")
	exec(t, `INSERT INTO tenant_identity (tenant_id, issuer, client_id, client_secret_sealed, redirect_url)
	         VALUES ($1, 'https://login.example/v2.0', 'c', $2, 'https://x/signin/callback')`, tenantA, sealed)
	key, transport := transportKey(t)
	bundle := moveBundleOf(t, f, key)
	devicesBefore := adminCount(t, `SELECT count(*) FROM devices WHERE tenant_id = $1`, tenantA)
	auditBefore := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1`, tenantA)

	// Leave the source: suspend, offboard, verified empty.
	ctx := context.Background()
	if err := f.g.dir.SetStatus(ctx, "kalesi", "suspended"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.g.dir.Offboard(ctx, "kalesi", "operator"); err != nil {
		t.Fatalf("offboard: %v", err)
	}
	exec(t, `DELETE FROM offboarding_log WHERE tenant_id = $1`, tenantA)
	exec(t, `DELETE FROM tenants WHERE id = $1`, tenantA) // the shell row too: this database plays the destination now
	if n := adminCount(t, `SELECT count(*) FROM devices WHERE tenant_id = $1`, tenantA); n != 0 {
		t.Fatal("the source still has devices")
	}

	// Arrive at the destination, under its own master.
	master, _ := secrets.NewAESSealer(sealKey)
	rep, err := f.g.dir.ImportTenant(ctx, bundle, directory.ImportInput{Transport: transport, Master: master, Region: "af-south", By: "operator"})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	// The audit log: the bundle carries what was there before the move
	// export wrote its own record (that record stays at the source), and
	// the import adds one of its own, so the count read after the export
	// is the count that lands.
	if rep.Landed["devices"] != devicesBefore || rep.Landed["audit_events"] != auditBefore {
		t.Fatalf("landed %v, want devices=%d audit=%d", rep.Landed, devicesBefore, auditBefore)
	}
	var status, region string
	queryRow(t, `SELECT status FROM tenants WHERE id = $1`, &status, tenantA)
	queryRow(t, `SELECT region FROM tenants WHERE id = $1`, &region, tenantA)
	if status != "suspended" || region != "af-south" {
		t.Fatalf("the tenant arrived %s in %s", status, region)
	}
	// The audit chain was rebuilt in order by the trigger: NULL is "holds",
	// anything else is the id of the first broken link.
	var brokenAt *int64
	queryRow(t, `SELECT app.verify_audit_chain($1)`, &brokenAt, tenantA)
	if brokenAt != nil {
		t.Fatalf("the imported audit chain breaks at row %d", *brokenAt)
	}

	// And it works: resumed, the console answers with the tenant's data,
	// a device authenticates, and the sealed secret opens under this
	// region's master through the tenant's re-wrapped key.
	if err := f.g.dir.SetStatus(ctx, "kalesi", "active"); err != nil {
		t.Fatal(err)
	}
	rec, body := do(t, f, req(t, "GET", hostA, "/api/devices", "a-super"))
	bodyJSON, _ := json.Marshal(body)
	if rec.Code != 200 || !strings.Contains(string(bodyJSON), "HQ-MBP-001") {
		t.Fatalf("devices after the move: %d %v", rec.Code, body)
	}
	dev := f.devices[tenantA][0]
	r := req(t, "GET", hostA, "/api/my/commands?wait=1", "")
	r.TLS = trustedCert(t, tenantA, dev)
	if rec, _ := do(t, f, r); rec.Code != 200 {
		t.Fatalf("a device cannot authenticate after the move: %d", rec.Code)
	}
	claim, _ := f.g.signer.Mint(tenantclaim.Claim{TenantID: tenantA, Subject: "test", Role: "super_admin", RequestID: uuid.NewString()}, time.Minute)
	fresh := secrets.NewKeyring(master) // no cache: the row has to carry the truth
	if err := f.g.store.WithTenant(ctx, claim, func(ctx context.Context, tx *data.Tx) error {
		var got []byte
		if err := tx.QueryRow(ctx, `SELECT client_secret_sealed FROM tenant_identity`).Scan(&got); err != nil {
			return err
		}
		plain, err := fresh.Open(ctx, tx, got)
		if err != nil {
			return err
		}
		if string(plain) != "the-client-secret" {
			t.Fatalf("the secret came out as %q", plain)
		}
		return nil
	}); err != nil {
		t.Fatalf("the moved secret does not open here: %v", err)
	}
}

// Reliability over coverage: a bundle that does not add up lands nothing.
func TestAnImportThatDoesNotAddUpChangesNothing(t *testing.T) {
	f := newFixture(t)
	baseline(t, f)
	key, transport := transportKey(t)
	files := unzipAll(t, moveBundleOf(t, f, key))
	plainExport := raw(t, f, req(t, "GET", hostA, "/api/export", "a-super")).Body.Bytes()
	ctx := context.Background()
	if err := f.g.dir.SetStatus(ctx, "kalesi", "suspended"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.g.dir.Offboard(ctx, "kalesi", "operator"); err != nil {
		t.Fatal(err)
	}
	exec(t, `DELETE FROM offboarding_log WHERE tenant_id = $1`, tenantA)
	exec(t, `DELETE FROM tenants WHERE id = $1`, tenantA)
	master, _ := secrets.NewAESSealer(sealKey)

	// One device line missing: the manifest says two, one lands.
	short := map[string]string{}
	for k, v := range files {
		short[k] = v
	}
	lines := strings.Split(strings.TrimSpace(files["devices.jsonl"]), "\n")
	short["devices.jsonl"] = lines[0] + "\n"
	_, err := f.g.dir.ImportTenant(ctx, rezip(t, short), directory.ImportInput{Transport: transport, Master: master, Region: "af-south", By: "operator"})
	if !errors.Is(err, directory.ErrImportMismatch) || !strings.Contains(err.Error(), "devices: sent 2, landed 1") {
		t.Fatalf("a short bundle was not refused in words: %v", err)
	}
	if n := adminCount(t, `SELECT count(*) FROM tenants WHERE id = $1`, tenantA); n != 0 {
		t.Fatal("a tenant row was committed from a bundle that did not add up")
	}

	// A row that belongs to another tenant: refused by the database, not
	// only by the tool.
	foreign := map[string]string{}
	for k, v := range files {
		foreign[k] = v
	}
	foreign["policies.jsonl"] = strings.ReplaceAll(files["policies.jsonl"], tenantA.String(), tenantB.String())
	_, err = f.g.dir.ImportTenant(ctx, rezip(t, foreign), directory.ImportInput{Transport: transport, Master: master, Region: "af-south", By: "operator"})
	if err == nil || !strings.Contains(err.Error(), "names another tenant") {
		t.Fatalf("a foreign row was accepted: %v", err)
	}
	if n := adminCount(t, `SELECT count(*) FROM policies WHERE tenant_id = $1`, tenantB); n != 0 {
		t.Fatal("a foreign row landed in another tenant")
	}
	if n := adminCount(t, `SELECT count(*) FROM tenants WHERE id = $1`, tenantA); n != 0 {
		t.Fatal("a tenant row was committed from a bundle with a foreign row")
	}

	// A plain export is not a move bundle and says so.
	if _, err := f.g.dir.ImportTenant(ctx, plainExport, directory.ImportInput{Transport: transport, Master: master}); !errors.Is(err, directory.ErrNotAMoveBundle) {
		t.Fatalf("an export was taken for a move bundle: %v", err)
	}
}
