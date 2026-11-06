package gateway

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

// T10: the export is everything, minus every secret, for the Super Admin.

func TestTheExportIsEverythingMinusTheSecrets(t *testing.T) {
	f := newFixture(t)
	baseline(t, f)
	mintToken(t, f, "a-super", "NAC")
	exec(t, `INSERT INTO tenant_identity (tenant_id, issuer, client_id, client_secret_sealed, redirect_url)
	         VALUES ($1, 'https://login.example/v2.0', 'c', '\x0102', 'https://x/signin/callback')
	         ON CONFLICT DO NOTHING`, tenantA)
	for _, bearer := range []string{"a-itadmin", "a-auditor", "a-helpdesk"} {
		if rec := raw(t, f, req(t, "GET", hostA, "/api/export", bearer)); rec.Code != http.StatusForbidden {
			t.Fatalf("%s exported the tenant: %d", bearer, rec.Code)
		}
	}
	rec := raw(t, f, req(t, "GET", hostA, "/api/export", "a-super"))
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("export: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("zip: %v", err)
	}
	files := map[string]string{}
	for _, zf := range zr.File {
		rc, _ := zf.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		files[zf.Name] = string(b)
	}
	for _, want := range []string{"devices.jsonl", "policies.jsonl", "audit_events.jsonl", "tenant_identity.jsonl", "integration_tokens.jsonl", "manifest.json"} {
		if _, ok := files[want]; !ok {
			t.Fatalf("the export has no %s", want)
		}
	}
	if !strings.Contains(files["devices.jsonl"], "HQ-MBP-001") || strings.Count(files["devices.jsonl"], "\n") != 2 {
		t.Fatalf("devices.jsonl: %q", files["devices.jsonl"])
	}
	if strings.Contains(files["devices.jsonl"], "arbor") {
		t.Fatal("the export crossed tenants")
	}
	// Secrets replaced, not carried.
	if !strings.Contains(files["tenant_identity.jsonl"], `"client_secret_sealed":"[not exported]"`) {
		t.Fatalf("the identity secret travelled: %q", files["tenant_identity.jsonl"])
	}
	if !strings.Contains(files["integration_tokens.jsonl"], `"token_hash":"[not exported]"`) {
		t.Fatalf("a token hash travelled: %q", files["integration_tokens.jsonl"])
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'tenant.exported'`, tenantA); n != 1 {
		t.Fatal("the export was not audited")
	}
	// While exporting, the console answers the export and nothing else.
	exec(t, `UPDATE tenants SET status = 'exporting' WHERE id = $1`, tenantA)
	if rec := raw(t, f, req(t, "GET", hostA, "/api/export", "a-super")); rec.Code != 200 {
		t.Fatalf("export while exporting: %d", rec.Code)
	}
	if rec, _ := do(t, f, req(t, "GET", hostA, "/api/devices", "a-super")); rec.Code != http.StatusForbidden {
		t.Fatalf("devices while exporting: %d", rec.Code)
	}
}
