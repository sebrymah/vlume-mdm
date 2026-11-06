package gateway

import (
	"net/http"
	"platform/internal/policy"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------- helpers

func savePolicy(t *testing.T, f fixture, bearer string, in map[string]any) (int, map[string]any) {
	t.Helper()
	rec, body := do(t, f, jsonReq(t, "POST", hostA, "/api/policies", bearer, in))
	return rec.Code, body
}

// reportAs posts a device's own report, on its own certificate, which is the
// only way a report can arrive.
func reportAs(t *testing.T, f fixture, host string, tenant, device uuid.UUID,
	rep map[string]any) (int, map[string]any) {
	t.Helper()
	r := jsonReq(t, "POST", host, "/api/devices/"+device.String()+"/report", "", rep)
	r.TLS = trustedCert(t, tenant, device)
	rec, body := do(t, f, r)
	return rec.Code, body
}

func baseline(t *testing.T, f fixture) {
	t.Helper()
	code, body := savePolicy(t, f, "a-itadmin", map[string]any{
		"name": "Baseline",
		"rules": map[string]any{
			"passcode_required":        true,
			"passcode_min_length":      8,
			"disk_encryption_required": true,
		},
	})
	if code != http.StatusCreated {
		t.Fatalf("baseline policy: %d %v", code, body)
	}
}

// ------------------------------------------------------------- the loop

func TestADeviceReportsAndIsJudged(t *testing.T) {
	f := newFixture(t)
	baseline(t, f)
	dev := f.devices[tenantA][0]

	code, body := reportAs(t, f, hostA, tenantA, dev, map[string]any{
		"passcode_set": true, "passcode_length": 12, "disk_encryption": true,
	})
	if code != 200 {
		t.Fatalf("report: %d %v", code, body)
	}
	if body["state"] != "compliant" {
		t.Fatalf("got %v, want compliant: %v", body["state"], body["findings"])
	}

	// The same device, now failing one rule.
	code, body = reportAs(t, f, hostA, tenantA, dev, map[string]any{
		"passcode_set": true, "passcode_length": 4, "disk_encryption": true,
	})
	if code != 200 {
		t.Fatalf("report: %d", code)
	}
	if body["state"] != "not_compliant" {
		t.Fatalf("got %v, want not_compliant", body["state"])
	}
	findings, _ := body["findings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %v", len(findings), findings)
	}
	first, _ := findings[0].(map[string]any)
	if !strings.Contains(first["saw"].(string), "4 characters") {
		t.Fatalf("the finding does not say what was seen: %v", first)
	}
	if first["from"] != "Baseline v1" {
		t.Fatalf("the finding does not name its policy: %v", first)
	}
}

// The verdict is the device's own state, so the dashboard and the device
// list reflect compliance without a second count that could disagree.
func TestTheVerdictBecomesTheDeviceState(t *testing.T) {
	f := newFixture(t)
	baseline(t, f)
	dev := f.devices[tenantA][0]

	if code, _ := reportAs(t, f, hostA, tenantA, dev, map[string]any{
		"passcode_set": true, "passcode_length": 12, "disk_encryption": false,
	}); code != 200 {
		t.Fatalf("report: %d", code)
	}

	_, body := do(t, f, req(t, "GET", hostA, "/api/devices/"+dev.String(), "a-itadmin"))
	if body["state"] != "not_compliant" {
		t.Fatalf("device state is %v, want not_compliant", body["state"])
	}
	if body["last_report_at"] == nil {
		t.Fatal("the device does not show when it last reported")
	}
}

// A device that has never reported has no verdict. Saying so is more useful
// than inventing one, and it is not the same as passing or failing.
func TestADeviceThatHasNeverReportedHasNoVerdict(t *testing.T) {
	f := newFixture(t)
	baseline(t, f)
	dev := f.devices[tenantA][0]

	rec, body := do(t, f, req(t, "GET", hostA,
		"/api/devices/"+dev.String()+"/compliance", "a-itadmin"))
	if rec.Code != 200 {
		t.Fatalf("got %d", rec.Code)
	}
	if body["state"] != "awaiting_first_boot" {
		t.Fatalf("got %v", body["state"])
	}
}

// ------------------------------------------------------- who may report

func TestOnlyADeviceMayReportAndOnlyAboutItself(t *testing.T) {
	f := newFixture(t)
	baseline(t, f)
	dev := f.devices[tenantA][0]
	other := f.devices[tenantA][1]

	// A console session, however privileged, cannot post a report. A fleet
	// is only evidence if the evidence comes from the machines.
	rec, _ := do(t, f, jsonReq(t, "POST", hostA,
		"/api/devices/"+dev.String()+"/report", "a-super",
		map[string]any{"passcode_set": true}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a console session reported for a device: got %d", rec.Code)
	}

	// A device reporting about a different device, on its own valid
	// certificate. 404 rather than 403, for the same reason everywhere
	// else: a forbidden answer confirms the device exists.
	r := jsonReq(t, "POST", hostA, "/api/devices/"+other.String()+"/report", "",
		map[string]any{"passcode_set": true})
	r.TLS = trustedCert(t, tenantA, dev)
	rec, _ = do(t, f, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("a device reported for another: got %d", rec.Code)
	}
}

// ---------------------------------------------------------- the merge

// End to end, through two real policies and a real device: the strictest
// value of each rule wins, so assigning a looser policy cannot relax a
// stricter one.
func TestTwoPoliciesMergeToTheStrictest(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]

	if code, body := savePolicy(t, f, "a-itadmin", map[string]any{
		"name": "Baseline", "rules": map[string]any{"passcode_min_length": 6},
	}); code != http.StatusCreated {
		t.Fatalf("baseline: %d %v", code, body)
	}
	if code, body := savePolicy(t, f, "a-itadmin", map[string]any{
		"name": "Finance", "rules": map[string]any{"passcode_min_length": 14},
	}); code != http.StatusCreated {
		t.Fatalf("finance: %d %v", code, body)
	}

	// Long enough for Baseline, short for Finance.
	_, body := reportAs(t, f, hostA, tenantA, dev, map[string]any{"passcode_length": 10})
	if body["state"] != "not_compliant" {
		t.Fatalf("the looser policy won: %v %v", body["state"], body["findings"])
	}
	findings := body["findings"].([]any)
	if from := findings[0].(map[string]any)["from"]; from != "Finance v2" &&
		from != "Finance v1" {
		t.Fatalf("the finding credits %v, expected Finance", from)
	}

	// And the effective view says the same thing, in words.
	_, eff := do(t, f, req(t, "GET", hostA, "/api/devices/"+dev.String()+"/policy", "a-itadmin"))
	requires := eff["requires"].([]any)
	joined := strings.Join(toStrings(requires), " | ")
	if !strings.Contains(joined, "at least 14") {
		t.Fatalf("the effective policy is %q", joined)
	}
	if strings.Contains(joined, "at least 6") {
		t.Fatalf("the relaxed value survived: %q", joined)
	}
}

func toStrings(in []any) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
}

// A policy scoped to one kind of device leaves the others alone.
func TestAScopedPolicyOnlyAppliesToTheDevicesItNames(t *testing.T) {
	f := newFixture(t)

	if code, body := savePolicy(t, f, "a-itadmin", map[string]any{
		"name": "Windows only", "os_family": "windows",
		"rules": map[string]any{"firewall_required": true},
	}); code != http.StatusCreated {
		t.Fatalf("policy: %d %v", code, body)
	}

	// The seeded tenant A devices are one macOS and one Windows, in name
	// order, so read them back rather than assuming.
	_, list := do(t, f, req(t, "GET", hostA, "/api/devices", "a-itadmin"))
	var mac, win uuid.UUID
	for _, d := range list["devices"].([]any) {
		m := d.(map[string]any)
		id := uuid.MustParse(m["id"].(string))
		switch m["os_family"] {
		case "macos":
			mac = id
		case "windows":
			win = id
		}
	}
	if mac == uuid.Nil || win == uuid.Nil {
		t.Fatal("the fixture no longer has one macOS and one Windows device")
	}

	// The Mac is not asked about a firewall at all.
	_, body := reportAs(t, f, hostA, tenantA, mac, map[string]any{})
	if body["state"] != "compliant" {
		t.Fatalf("a macOS device was judged by a Windows policy: %v", body["findings"])
	}
	// The Windows machine is, and did not say.
	_, body = reportAs(t, f, hostA, tenantA, win, map[string]any{})
	if body["state"] != "state_unknown" {
		t.Fatalf("the Windows device is %v, want state_unknown", body["state"])
	}
}

// Isolation, at the policy layer. Arbor's policies have nothing to do with
// Kalesi's devices.
func TestOneTenantsPolicyDoesNotJudgeAnothersDevices(t *testing.T) {
	f := newFixture(t)

	// Arbor writes a demanding policy.
	rec, body := do(t, f, jsonReq(t, "POST", hostB, "/api/policies", "b-itadmin",
		map[string]any{"name": "Arbor strict",
			"rules": map[string]any{"passcode_min_length": 20}}))
	if rec.Code != http.StatusCreated {
		t.Fatalf("arbor policy: %d %v", rec.Code, body)
	}

	// A Kalesi device with a short passcode is untouched by it.
	dev := f.devices[tenantA][0]
	_, got := reportAs(t, f, hostA, tenantA, dev, map[string]any{"passcode_length": 4})
	if got["state"] != "compliant" {
		t.Fatalf("a Kalesi device was judged by Arbor's policy: %v", got["findings"])
	}

	// And Kalesi cannot see that the policy exists.
	_, list := do(t, f, req(t, "GET", hostA, "/api/policies", "a-itadmin"))
	if n := len(list["policies"].([]any)); n != 0 {
		t.Fatalf("Kalesi sees %d policies", n)
	}
}

// ---------------------------------------------------- the administrative hold

// The one that matters most in this file. A device is quarantined because a
// person put it there. A cheerful report from a laptop that has just been
// wiped must not undo that.
func TestAQuarantinedDeviceStaysQuarantined(t *testing.T) {
	f := newFixture(t)
	baseline(t, f)
	dev := f.devices[tenantA][0]

	exec(t, `UPDATE devices SET state = 'quarantined' WHERE id = $1`, dev)

	code, body := reportAs(t, f, hostA, tenantA, dev, map[string]any{
		"passcode_set": true, "passcode_length": 12, "disk_encryption": true,
	})
	if code != 200 {
		t.Fatalf("report: %d %v", code, body)
	}
	// The verdict itself is recorded, and it is honest: the device really
	// does meet the rules.
	if body["state"] != "compliant" {
		t.Fatalf("the verdict is %v", body["state"])
	}

	// The device's own state is not touched.
	_, d := do(t, f, req(t, "GET", hostA, "/api/devices/"+dev.String(), "a-itadmin"))
	if d["state"] != "quarantined" {
		t.Fatalf("a good report released a quarantined device: now %v", d["state"])
	}
}

// The database says the same thing, so a future writer that forgets the Go
// check still cannot do it.
func TestTheDatabaseAlsoRefusesToReleaseAQuarantinedDevice(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]
	exec(t, `UPDATE devices SET state = 'quarantined' WHERE id = $1`, dev)

	err := execErr(t, `UPDATE devices SET state = 'compliant' WHERE id = $1`, dev)
	if err == nil {
		t.Fatal("the database let evaluation release a quarantined device")
	}
	if !strings.Contains(err.Error(), "quarantined") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	// A person may still move it somewhere administrative.
	if err := execErr(t, `UPDATE devices SET state = 'retired' WHERE id = $1`, dev); err != nil {
		t.Fatalf("an administrator could not retire a quarantined device: %v", err)
	}
}

// ---------------------------------------------------------------- authoring

func TestSavingAPolicyMakesANewVersionAndRetiresTheOld(t *testing.T) {
	f := newFixture(t)

	if code, _ := savePolicy(t, f, "a-itadmin", map[string]any{
		"name": "Baseline", "rules": map[string]any{"passcode_min_length": 6},
	}); code != http.StatusCreated {
		t.Fatal("first version")
	}
	code, body := savePolicy(t, f, "a-itadmin", map[string]any{
		"name": "Baseline", "rules": map[string]any{"passcode_min_length": 10},
	})
	if code != http.StatusCreated {
		t.Fatalf("second version: %d %v", code, body)
	}
	if body["version"] != float64(2) {
		t.Fatalf("got version %v, want 2", body["version"])
	}

	_, list := do(t, f, req(t, "GET", hostA, "/api/policies", "a-itadmin"))
	all := list["policies"].([]any)
	if len(all) != 2 {
		t.Fatalf("got %d rows, want both versions kept", len(all))
	}
	active := 0
	for _, p := range all {
		if p.(map[string]any)["active"] == true {
			active++
		}
	}
	if active != 1 {
		t.Fatalf("%d versions are live at once", active)
	}

	// Only the live version is applied.
	dev := f.devices[tenantA][0]
	_, got := reportAs(t, f, hostA, tenantA, dev, map[string]any{"passcode_length": 8})
	if got["state"] != "not_compliant" {
		t.Fatalf("the superseded version was applied: %v", got["state"])
	}
}

// A typo in a rule name is refused at the point someone typed it, with the
// list of rules that do exist.
func TestATypoInARuleNameIsRefusedWithHelp(t *testing.T) {
	f := newFixture(t)
	code, body := savePolicy(t, f, "a-itadmin", map[string]any{
		"name": "Baseline", "rules": map[string]any{"passcode_minimum_length": 8},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", code)
	}
	msg, _ := body["error"].(string)
	if !strings.Contains(msg, "passcode_minimum_length") {
		t.Fatalf("the message does not quote what was typed: %q", msg)
	}
	if !strings.Contains(msg, "passcode_min_length") {
		t.Fatalf("the message does not say what the rules are: %q", msg)
	}
}

func TestABadScopeIsRefused(t *testing.T) {
	f := newFixture(t)
	for _, in := range []map[string]any{
		{"name": "x", "os_family": "beos", "rules": map[string]any{}},
		{"name": "x", "ownership": "leased", "rules": map[string]any{}},
		{"name": "  ", "rules": map[string]any{}},
	} {
		if code, _ := savePolicy(t, f, "a-itadmin", in); code != http.StatusBadRequest {
			t.Fatalf("%v: got %d, want 400", in, code)
		}
	}
}

func TestOnlyTheRolesInTheMatrixMayChangePolicy(t *testing.T) {
	f := newFixture(t)
	for _, bearer := range []string{"a-helpdesk", "a-auditor", "a-secmgr", "a-employee"} {
		if code, _ := savePolicy(t, f, bearer, map[string]any{
			"name": "x", "rules": map[string]any{},
		}); code != http.StatusForbidden {
			t.Fatalf("%s wrote a policy: got %d", bearer, code)
		}
	}
	for _, bearer := range []string{"a-super", "a-itadmin"} {
		if code, _ := savePolicy(t, f, bearer, map[string]any{
			"name": "ok-" + bearer, "rules": map[string]any{},
		}); code != http.StatusCreated {
			t.Fatalf("%s could not write a policy: got %d", bearer, code)
		}
	}
	// Reading is part of seeing a device.
	rec, _ := do(t, f, req(t, "GET", hostA, "/api/policies", "a-helpdesk"))
	if rec.Code != 200 {
		t.Fatalf("helpdesk could not read policies: %d", rec.Code)
	}
}

func TestRetiringAPolicyStopsItApplying(t *testing.T) {
	f := newFixture(t)
	baseline(t, f)
	dev := f.devices[tenantA][0]

	_, body := reportAs(t, f, hostA, tenantA, dev, map[string]any{"passcode_length": 4})
	if body["state"] != "not_compliant" {
		t.Fatalf("expected a failure first: %v", body["state"])
	}

	rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/policies/Baseline/retire",
		"a-itadmin", map[string]any{}))
	if rec.Code != 200 {
		t.Fatalf("retire: %d", rec.Code)
	}
	_, body = reportAs(t, f, hostA, tenantA, dev, map[string]any{"passcode_length": 4})
	if body["state"] != "compliant" {
		t.Fatalf("a retired policy still applied: %v %v", body["state"], body["findings"])
	}

	// Retiring twice is a 404, not a silent success.
	rec, _ = do(t, f, jsonReq(t, "POST", hostA, "/api/policies/Baseline/retire",
		"a-itadmin", map[string]any{}))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("retiring twice got %d", rec.Code)
	}
}

// ---------------------------------------------------------------- the rest

// A verdict that was fresh when it was reached is not fresh forever, and a
// console showing a green row for a laptop last seen in March would be lying
// with a straight face.
func TestAStaleVerdictIsRecheckedWhenItIsRead(t *testing.T) {
	f := newFixture(t)
	baseline(t, f)
	dev := f.devices[tenantA][0]

	if code, body := reportAs(t, f, hostA, tenantA, dev, map[string]any{
		"passcode_set": true, "passcode_length": 12, "disk_encryption": true,
	}); code != 200 || body["state"] != "compliant" {
		t.Fatalf("expected a pass first: %d %v", code, body)
	}

	exec(t, `UPDATE device_compliance SET reported_at = now() - interval '30 days'
	          WHERE device_id = $1`, dev)

	_, body := do(t, f, req(t, "GET", hostA,
		"/api/devices/"+dev.String()+"/compliance", "a-itadmin"))
	if body["state"] != "state_unknown" {
		t.Fatalf("a month-old pass still reads as %v", body["state"])
	}
}

func TestPolicyAndReportingAreAudited(t *testing.T) {
	f := newFixture(t)
	baseline(t, f)
	dev := f.devices[tenantA][0]
	if code, _ := reportAs(t, f, hostA, tenantA, dev,
		map[string]any{"passcode_set": true}); code != 200 {
		t.Fatal("report")
	}

	_, body := do(t, f, req(t, "GET", hostA, "/api/audit", "a-auditor"))
	events := toStrings(nil)
	for _, e := range body["events"].([]any) {
		events = append(events, e.(map[string]any)["action"].(string))
	}
	joined := strings.Join(events, " ")
	for _, want := range []string{"policy.save", "device.report"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("%s is not in the audit log: %s", want, joined)
		}
	}
}

// The console page renders the policies and names the rules it understands,
// so an administrator writing one does not have to guess.
func TestThePoliciesPageNamesTheRulesItUnderstands(t *testing.T) {
	f := newFixture(t)
	baseline(t, f)

	rec, body := getHTML(t, f, hostA, "/policies", "a-itadmin")
	if rec.Code != 200 {
		t.Fatalf("got %d", rec.Code)
	}
	for _, want := range []string{"Baseline", "passcode_min_length", "strictest"} {
		if !strings.Contains(body, want) {
			t.Fatalf("the page does not mention %q", want)
		}
	}
	// Helpdesk may read it and must not be offered the form.
	_, body = getHTML(t, f, hostA, "/policies", "a-helpdesk")
	if strings.Contains(body, "Save as a new version") {
		t.Fatal("helpdesk was offered the policy form")
	}
}

// F6: rollback is a new version with the old body. History stays a line.
func TestRollingBackMakesANewVersionWithTheOldRules(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]
	baseline(t, f) // v1: passcode 8
	if code, body := savePolicy(t, f, "a-itadmin", map[string]any{
		"name": "Baseline", "rules": map[string]any{"passcode_required": true, "passcode_min_length": 14},
	}); code != http.StatusCreated {
		t.Fatalf("v2: %d %v", code, body)
	}
	// Under v2 a 10-character passcode fails.
	if code, b := reportAs(t, f, hostA, tenantA, dev, map[string]any{"passcode_set": true, "passcode_length": 10, "disk_encryption": true}); code != 200 || b["state"] != "not_compliant" {
		t.Fatalf("under v2: %d %v", code, b)
	}
	// Roll back to v1: a NEW v3 with v1's body, v2 switched off.
	rec, body := do(t, f, jsonReq(t, "POST", hostA, "/api/policies/Baseline/rollback", "a-itadmin",
		map[string]any{"version": 1}))
	if rec.Code != http.StatusCreated || body["version"] != float64(3) || body["active"] != true {
		t.Fatalf("rollback: %d %v", rec.Code, body)
	}
	if n := adminCount(t, `SELECT count(*) FROM policies WHERE tenant_id = $1 AND name = 'Baseline' AND active`, tenantA); n != 1 {
		t.Fatalf("%d live versions after rollback", n)
	}
	if n := adminCount(t, `SELECT count(*) FROM policies WHERE tenant_id = $1 AND name = 'Baseline'`, tenantA); n != 3 {
		t.Fatalf("%d versions: history is not a straight line", n)
	}
	// And the same report now passes: v3 asks for 8.
	if code, b := reportAs(t, f, hostA, tenantA, dev, map[string]any{"passcode_set": true, "passcode_length": 10, "disk_encryption": true}); code != 200 || b["state"] != "compliant" {
		t.Fatalf("under v3: %d %v", code, b)
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'policy.rollback'`, tenantA); n != 1 {
		t.Fatal("the rollback was not audited")
	}
	// A version that never existed, and a role that may not.
	if rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/policies/Baseline/rollback", "a-itadmin", map[string]any{"version": 9})); rec.Code != http.StatusNotFound {
		t.Fatalf("restoring v9: %d", rec.Code)
	}
	if rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/policies/Baseline/rollback", "a-helpdesk", map[string]any{"version": 1})); rec.Code != http.StatusForbidden {
		t.Fatalf("the help desk rolled back: %d", rec.Code)
	}
}

// F5: every template parses, and saving one is an ordinary save.
func TestEveryTemplateIsAPolicyTheEngineUnderstands(t *testing.T) {
	f := newFixture(t)
	rec, body := do(t, f, req(t, "GET", hostA, "/api/policies/templates", "a-helpdesk"))
	ts, _ := body["templates"].([]any)
	if rec.Code != 200 || len(ts) < 3 {
		t.Fatalf("templates: %d %v", rec.Code, body)
	}
	for _, raw := range ts {
		tpl := raw.(map[string]any)
		code, saved := do(t, f, jsonReq(t, "POST", hostA, "/api/policies", "a-itadmin", map[string]any{
			"name": "From " + tpl["key"].(string), "os_family": tpl["os_family"], "ownership": tpl["ownership"],
			"rules": tpl["rules"],
		}))
		if code.Code != http.StatusCreated {
			t.Fatalf("template %v did not save: %d %v", tpl["key"], code.Code, saved)
		}
	}
	// The page offers them and fills the form from one.
	_, page := getHTML(t, f, hostA, "/policies?template=phones", "a-itadmin")
	if !strings.Contains(page, "Start from a template") || !strings.Contains(page, `"on_failure": "quarantine"`) {
		t.Fatal("the template did not fill the form")
	}
}

// F5: a starting point for every kind of device the engine distinguishes.
// A tenant with Android phones, Windows PCs and Macs, owned and personal,
// finds a template for each rather than a blank form.
func TestTheTemplatesCoverEveryKindOfDevice(t *testing.T) {
	osFamilies, ownerships := policy.TemplateCoverage()
	for _, os := range []string{"macos", "windows", "android"} {
		if !osFamilies[os] {
			t.Fatalf("no template is scoped to %s", os)
		}
	}
	for _, own := range []string{"company", "personal"} {
		if !ownerships[own] {
			t.Fatalf("no template is scoped to %s devices", own)
		}
	}
	// And each is a policy the engine accepts, with a sentence saying why.
	for _, tpl := range policy.Templates() {
		if strings.TrimSpace(tpl.Why) == "" || strings.TrimSpace(tpl.Title) == "" {
			t.Fatalf("template %s has no title or reason", tpl.Key)
		}
		if _, err := policy.Parse(tpl.Key, []byte(tpl.Body)); err != nil {
			t.Fatalf("template %s does not parse: %v", tpl.Key, err)
		}
	}
}
