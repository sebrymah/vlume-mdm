package gateway

import (
	"net/http"
	"testing"
)

// A device certificate is a credential held on a machine that can be stolen,
// handed to a repair shop, or rooted by the person carrying it. What it may
// do has to be the shortest list in the product: report on itself, read its
// own instructions, say it has carried them out.
//
// Until this sprint it was granted it_admin. Everything below would have
// worked, which means one compromised laptop could have wiped the fleet.
func TestADeviceCertificateCannotActAsAnAdministrator(t *testing.T) {
	f := newFixture(t)
	me := f.devices[tenantA][0]
	other := f.devices[tenantA][1]

	cert := trustedCert(t, tenantA, me)

	cases := []struct {
		what   string
		method string
		path   string
		body   any
	}{
		{"enumerate the fleet", "GET", "/api/devices", nil},
		{"read another device", "GET", "/api/devices/" + other.String(), nil},
		{"lock another device", "POST", "/api/devices/" + other.String() + "/lock",
			map[string]any{"reason": "because it can"}},
		{"lock itself", "POST", "/api/devices/" + me.String() + "/lock",
			map[string]any{"reason": "because it can"}},
		{"wipe another device", "POST", "/api/devices/" + other.String() + "/wipe",
			map[string]any{"reason": "because it can", "scope": "all"}},
		{"rewrite the policy", "POST", "/api/policies",
			map[string]any{"name": "Nothing required", "rules": map[string]any{}}},
		{"retire a policy", "POST", "/api/policies/Baseline/retire", map[string]any{}},
		{"read the audit log", "GET", "/api/audit", nil},
		{"list enrolments", "GET", "/api/enrolments", nil},
		{"invite a device", "POST", "/api/enrolments",
			map[string]any{"label": "x", "ownership": "company", "os_family": "macos"}},
		{"read the whole command queue", "GET", "/api/commands", nil},
		{"approve a wipe", "POST", "/api/commands/" + other.String() + "/approve",
			map[string]any{}},
	}

	for _, c := range cases {
		var r *http.Request
		if c.body == nil {
			r = req(t, c.method, hostA, c.path, "")
		} else {
			r = jsonReq(t, c.method, hostA, c.path, "", c.body)
		}
		r.TLS = cert
		rec, _ := do(t, f, r)
		if rec.Code != http.StatusForbidden {
			t.Errorf("a device certificate could %s: got %d, want 403", c.what, rec.Code)
		}
	}
}

// What it MAY do, so that locking it down did not lock it out.
func TestADeviceCertificateCanDoItsOwnJob(t *testing.T) {
	f := newFixture(t)
	me := f.devices[tenantA][0]
	cert := trustedCert(t, tenantA, me)

	// Report on itself.
	r := jsonReq(t, "POST", hostA, "/api/devices/"+me.String()+"/report", "",
		map[string]any{"passcode_set": true})
	r.TLS = cert
	if rec, body := do(t, f, r); rec.Code != 200 {
		t.Fatalf("a device could not report on itself: %d %v", rec.Code, body)
	}

	// Read its own instructions.
	r = req(t, "GET", hostA, "/api/my/commands", "")
	r.TLS = cert
	rec, body := do(t, f, r)
	if rec.Code != 200 {
		t.Fatalf("a device could not read its own commands: %d %v", rec.Code, body)
	}
	if _, ok := body["commands"]; !ok {
		t.Fatalf("no command list came back: %v", body)
	}
}

// Its own queue is its own. The route exists separately from the
// administrator's listing precisely so that there is no branch inside a
// shared handler to get wrong.
func TestADeviceSeesOnlyItsOwnCommands(t *testing.T) {
	f := newFixture(t)
	me := f.devices[tenantA][0]
	other := f.devices[tenantA][1]

	// An administrator asks for a lock on each device.
	for _, d := range []string{me.String(), other.String()} {
		rec, body := do(t, f, jsonReq(t, "POST", hostA, "/api/devices/"+d+"/lock",
			"a-itadmin", map[string]any{"reason": "a drill"}))
		if rec.Code != http.StatusAccepted {
			t.Fatalf("lock %s: %d %v", d, rec.Code, body)
		}
	}

	r := req(t, "GET", hostA, "/api/my/commands", "")
	r.TLS = trustedCert(t, tenantA, me)
	_, body := do(t, f, r)
	cmds, _ := body["commands"].([]any)
	if len(cmds) != 1 {
		t.Fatalf("a device sees %d commands, want only its own 1", len(cmds))
	}
	if got := cmds[0].(map[string]any)["device_id"]; got != me.String() {
		t.Fatalf("a device was handed another device's work: %v", got)
	}
}

// A session, however privileged, is not a device and cannot use the device's
// own route. Otherwise an administrator could acknowledge work on a device's
// behalf and the acknowledgement would mean nothing.
func TestASessionCannotUseTheDeviceRoute(t *testing.T) {
	f := newFixture(t)
	rec, _ := do(t, f, req(t, "GET", hostA, "/api/my/commands", "a-super"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a console session read a device's queue: got %d", rec.Code)
	}
}
