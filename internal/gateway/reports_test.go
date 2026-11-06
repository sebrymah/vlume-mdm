package gateway

import (
	"bytes"
	"context"
	"encoding/csv"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"platform/internal/authz"
	"platform/internal/data"
	"platform/internal/tenantclaim"
)

// F18. The report is an export of tenant data: tenant-branded, audited,
// for the roles that may see devices, and scheduled through the same
// notification targets as everything else.

func TestTheComplianceReportListsEveryDeviceWithItsVerdict(t *testing.T) {
	f := newFixture(t)
	baseline(t, f)
	devs := f.devices[tenantA]
	// One compliant, one failing, so the report has both a green row and a
	// findings section.
	if code, b := reportAs(t, f, hostA, tenantA, devs[0], map[string]any{"passcode_set": true, "passcode_length": 12, "disk_encryption": true}); code != 200 || b["state"] != "compliant" {
		t.Fatalf("report 1: %d %v", code, b)
	}
	if code, b := reportAs(t, f, hostA, tenantA, devs[1], map[string]any{"passcode_set": false, "disk_encryption": true}); code != 200 || b["state"] != "not_compliant" {
		t.Fatalf("report 2: %d %v", code, b)
	}

	// Who holds it and what the network knows it by travel with the row.
	assign(t, devs[0], "kemi@kalesi.example")
	if code, _ := reportAs(t, f, hostA, tenantA, devs[0], withMACs(map[string]any{"passcode_set": true, "passcode_length": 12, "disk_encryption": true}, "3c:22:fb:aa:bb:01")); code != 200 {
		t.Fatal("report with mac")
	}
	rec := raw(t, f, req(t, "GET", hostA, "/api/reports/compliance?format=csv", "a-auditor"))
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("csv: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	rows, err := csv.NewReader(bytes.NewReader(rec.Body.Bytes())).ReadAll()
	if err != nil {
		t.Fatalf("csv parse: %v", err)
	}
	if len(rows) != 3 || rows[0][0] != "device" || rows[0][5] != "verdict" {
		t.Fatalf("csv shape: %v", rows)
	}
	verdicts := map[string]string{}
	findings := map[string]string{}
	for _, r := range rows[1:] {
		verdicts[r[0]], findings[r[0]] = r[5], r[7]
	}
	if verdicts["HQ-MBP-001"] != "compliant" || verdicts["HQ-WIN-004"] != "not_compliant" {
		t.Fatalf("verdicts: %v", verdicts)
	}
	if !strings.Contains(findings["HQ-WIN-004"], "a passcode must be set") || !strings.Contains(findings["HQ-WIN-004"], "Baseline v1") {
		t.Fatalf("the failing row does not say what is wrong and who asked: %q", findings["HQ-WIN-004"])
	}
	if rows[0][9] != "held_by" || rows[0][10] != "mac_addresses" {
		t.Fatalf("csv columns: %v", rows[0])
	}
	for _, r := range rows[1:] {
		if r[0] == "HQ-MBP-001" && (r[9] != "kemi@kalesi.example" || r[10] != "3c:22:fb:aa:bb:01") {
			t.Fatalf("the held-by and mac columns: %q %q", r[9], r[10])
		}
	}
	pdf := raw(t, f, req(t, "GET", hostA, "/reports/compliance.pdf", "a-auditor"))
	if pdf.Code != 200 || !strings.Contains(pdf.Body.String(), "held by kemi@kalesi.example  MAC 3c:22:fb:aa:bb:01") {
		t.Fatalf("the PDF does not say who holds the device and its address (%d)", pdf.Code)
	}
	// Only this tenant's devices. Tenant B has three.
	if n := adminCount(t, `SELECT count(*) FROM devices WHERE tenant_id = $1`, tenantB); n != 3 || len(rows)-1 != 2 {
		t.Fatalf("the report crossed tenants: %d rows", len(rows)-1)
	}
	// Audited, with the format.
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'report.generated' AND object_ref LIKE 'compliance.csv%'`, tenantA); n != 1 {
		t.Fatal("making the report was not audited")
	}
}

func TestThePDFCarriesTheTenantsBrandAndAFooterOnEveryPage(t *testing.T) {
	f := newFixture(t)
	// Enough devices for two pages.
	exec(t, `INSERT INTO devices (tenant_id, name, serial, os_family, state)
	         SELECT $1, 'BULK-' || lpad(g::text, 3, '0'), 'SN-BULK-' || g, 'macos', 'state_unknown'
	           FROM generate_series(1, 70) g`, tenantA)
	rec := raw(t, f, req(t, "GET", hostA, "/reports/compliance.pdf", "a-itadmin"))
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/pdf" {
		t.Fatalf("pdf: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	body := rec.Body.String()
	if !strings.HasPrefix(body, "%PDF-1.4") || !strings.HasSuffix(strings.TrimSpace(body), "%%EOF") {
		t.Fatal("not a PDF")
	}
	brand := adminString(t, `SELECT product_name FROM tenant_branding WHERE tenant_id = $1`, tenantA)
	if !strings.Contains(body, "("+brand+") Tj") {
		t.Fatalf("the PDF does not carry the tenant's product name %q", brand)
	}
	for _, operator := range []string{"MDM Platform", "Operator", "platform"} {
		if strings.Contains(body, "("+operator) {
			t.Fatalf("the PDF names the operator: %q", operator)
		}
	}
	if !strings.Contains(body, "Page 1 of 2") || !strings.Contains(body, "Page 2 of 2") {
		t.Fatalf("the footer does not number both pages")
	}
	if !strings.Contains(body, "Compliance report  \xb7  Page 1 of 2") {
		t.Fatal("the footer does not carry the title before the page number")
	}
	if !strings.Contains(body, "/Count 2") {
		t.Fatal("the page tree does not count two pages")
	}
	if !strings.Contains(rec.Header().Get("Content-Disposition"), "-compliance-") {
		t.Fatalf("filename: %s", rec.Header().Get("Content-Disposition"))
	}
}

func TestOnlyRolesThatSeeDevicesGetTheReport(t *testing.T) {
	f := newFixture(t)
	rec, _ := do(t, f, req(t, "GET", hostA, "/api/reports/compliance", "a-employee"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("an employee got the report: %d", rec.Code)
	}
	for _, bearer := range []string{"a-auditor", "a-helpdesk", "a-secmgr"} {
		if rec, _ := do(t, f, req(t, "GET", hostA, "/api/reports/compliance", bearer)); rec.Code != 200 {
			t.Fatalf("%s did not get the report: %d", bearer, rec.Code)
		}
	}
}

func TestTheWeeklyReportGoesOnceAWeekThroughTheTenantsOwnTarget(t *testing.T) {
	f := newFixture(t)
	claim, err := f.g.signer.Mint(tenantclaim.Claim{
		TenantID: tenantA, Subject: "system:weekly-report", Role: string(authz.Operator),
		RequestID: uuid.NewString(),
	}, time.Minute)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	run := func() bool {
		var sent bool
		if err := f.g.store.WithTenant(context.Background(), claim, func(ctx context.Context, tx *data.Tx) error {
			var err error
			sent, err = f.g.WeeklyReport(ctx, tx, hostA, time.Now().UTC())
			return err
		}); err != nil {
			t.Fatalf("weekly: %v", err)
		}
		return sent
	}
	sent1, sent2 := run(), run()
	if !sent1 || sent2 {
		t.Fatalf("first run sent=%v, second run sent=%v; want once", sent1, sent2)
	}
	if n := adminCount(t, `SELECT count(*) FROM notifications WHERE tenant_id = $1 AND topic = 'report.compliance'`, tenantA); n != 1 {
		t.Fatalf("%d weekly messages", n)
	}
	subject := adminString(t, `SELECT subject FROM notifications WHERE tenant_id = $1 AND topic = 'report.compliance'`, tenantA)
	if !strings.Contains(subject, "devices:") {
		t.Fatalf("the weekly subject does not carry the summary: %q", subject)
	}
	body := adminString(t, `SELECT body FROM notifications WHERE tenant_id = $1 AND topic = 'report.compliance'`, tenantA)
	if !strings.Contains(body, "https://"+hostA+"/reports/compliance.pdf") {
		t.Fatalf("the weekly message does not link the download: %q", body)
	}
}

// raw serves a request and hands back the recorder untouched: do() decodes
// the body as JSON, and a CSV or a PDF is not that.
func raw(t *testing.T, f fixture, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	return rec
}
