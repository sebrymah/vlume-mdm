package gateway

import (
	"bufio"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func sleepMs(n int) { time.Sleep(time.Duration(n) * time.Millisecond) }

// F19. A stream, not a notification: no gaps, no repeats, the tenant's
// name on every line, and a cursor that moves only when the collector has
// taken the event.

type fakeSIEM struct {
	ln    net.Listener
	mu    sync.Mutex
	lines []string
}

func newFakeSIEM(t *testing.T) *fakeSIEM {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeSIEM{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				sc := bufio.NewScanner(c)
				for sc.Scan() {
					f.mu.Lock()
					f.lines = append(f.lines, sc.Text())
					f.mu.Unlock()
				}
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeSIEM) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.lines)
}

func (f *fakeSIEM) all() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.lines...)
}

func waitLines(t *testing.T, f *fakeSIEM, n int) {
	t.Helper()
	for i := 0; i < 50 && f.count() < n; i++ {
		sleepMs(20)
	}
}

func TestEveryAuditEventReachesTheSIEMOnceInCEFWithTheTenantsName(t *testing.T) {
	f := newFixture(t)
	siem := newFakeSIEM(t)
	// The destination is an ordinary target.
	rec, body := do(t, f, jsonReq(t, "POST", hostA, "/api/notifications", "a-itadmin",
		map[string]any{"topic": "siem.audit", "kind": "syslog", "endpoint": "syslog://" + siem.ln.Addr().String()}))
	if rec.Code >= 300 {
		t.Fatalf("target: %d %v", rec.Code, body)
	}
	// Some events: a lock, a policy save.
	baseline(t, f)
	do(t, f, jsonReq(t, "POST", hostA, "/api/devices/"+f.devices[tenantA][0].String()+"/lock", "a-itadmin",
		map[string]any{"reason": "Reported stolen"}))
	events := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1`, tenantA)

	rec, body = do(t, f, req(t, "POST", hostA, "/api/siem/export", "a-itadmin"))
	if rec.Code != 200 || int(body["sent"].(float64)) != events {
		t.Fatalf("export: %d %v (want %d)", rec.Code, body, events)
	}
	waitLines(t, siem, events)
	lines := siem.all()
	if len(lines) != events {
		t.Fatalf("%d lines at the SIEM, want %d", len(lines), events)
	}
	brand := adminString(t, `SELECT product_name FROM tenant_branding WHERE tenant_id = $1`, tenantA)
	for _, l := range lines {
		if !strings.Contains(l, "CEF:0|"+brand+"|Device Management|1|") {
			t.Fatalf("a line without the tenant's name as vendor: %q", l)
		}
		if strings.Contains(l, "Operator") {
			t.Fatalf("a line names the operator: %q", l)
		}
		if !strings.Contains(l, "cs2=kalesi") || !strings.Contains(l, "cs3Label=hash cs3=") {
			t.Fatalf("a line without tenant and hash: %q", l)
		}
	}
	// A second export sends nothing: the cursor is at the end.
	rec, body = do(t, f, req(t, "POST", hostA, "/api/siem/export", "a-itadmin"))
	if rec.Code != 200 || body["sent"] != float64(0) {
		t.Fatalf("second export: %d %v", rec.Code, body)
	}
	// Tenant B's events never reach tenant A's SIEM.
	do(t, f, jsonReq(t, "POST", hostB, "/api/policies", "b-itadmin",
		map[string]any{"name": "B", "rules": map[string]any{"passcode_required": true}}))
	do(t, f, req(t, "POST", hostA, "/api/siem/export", "a-itadmin"))
	for _, l := range siem.all() {
		if strings.Contains(l, "cs2=arbor") {
			t.Fatal("a tenant B event reached tenant A's SIEM")
		}
	}
	_, status := do(t, f, req(t, "GET", hostA, "/api/siem/status", "a-auditor"))
	if status["behind"] != float64(0) || status["sent_total"] != float64(events) {
		t.Fatalf("status: %v", status)
	}
}

func TestACollectorThatIsDownLosesNothing(t *testing.T) {
	f := newFixture(t)
	siem := newFakeSIEM(t)
	do(t, f, jsonReq(t, "POST", hostA, "/api/notifications", "a-itadmin",
		map[string]any{"topic": "siem.audit", "kind": "syslog", "endpoint": "syslog://" + siem.ln.Addr().String()}))
	baseline(t, f)
	before := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1`, tenantA)
	// The collector goes down.
	siem.ln.Close()
	rec, body := do(t, f, req(t, "POST", hostA, "/api/siem/export", "a-itadmin"))
	if rec.Code != http.StatusBadGateway || body["sent"] != float64(0) {
		t.Fatalf("export to a dead collector: %d %v", rec.Code, body)
	}
	_, status := do(t, f, req(t, "GET", hostA, "/api/siem/status", "a-auditor"))
	if status["last_audit_id"] != float64(0) || status["last_error"] == "" || int(status["behind"].(float64)) < before {
		t.Fatalf("after a failure the cursor moved or the error is unrecorded: %v", status)
	}
	// A new collector on the same address is not possible; point at a new
	// one and everything from the start arrives, once.
	siem2 := newFakeSIEM(t)
	do(t, f, jsonReq(t, "POST", hostA, "/api/notifications", "a-itadmin",
		map[string]any{"topic": "siem.audit", "kind": "syslog", "endpoint": "syslog://" + siem2.ln.Addr().String()}))
	events := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1`, tenantA)
	rec, body = do(t, f, req(t, "POST", hostA, "/api/siem/export", "a-itadmin"))
	if rec.Code != 200 || int(body["sent"].(float64)) != events {
		t.Fatalf("resume: %d %v want %d", rec.Code, body, events)
	}
	waitLines(t, siem2, events)
	if n := siem2.count(); n != events {
		t.Fatalf("%d lines after resume, want %d", n, events)
	}
}

func TestLEEFAndABadDestinationAreBothHonoured(t *testing.T) {
	f := newFixture(t)
	siem := newFakeSIEM(t)
	rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/notifications", "a-itadmin",
		map[string]any{"topic": "siem.audit", "kind": "syslog", "endpoint": "syslog://" + siem.ln.Addr().String() + "?format=leef"}))
	if rec.Code >= 300 {
		t.Fatalf("leef target: %d", rec.Code)
	}
	do(t, f, req(t, "POST", hostA, "/api/siem/export", "a-itadmin"))
	waitLines(t, siem, 1)
	if lines := siem.all(); len(lines) == 0 || !strings.HasPrefix(lines[0][strings.Index(lines[0], "LEEF"):], "LEEF:2.0|") {
		t.Fatalf("not LEEF: %v", lines)
	}
	for _, bad := range []string{"tcp://10.0.0.1:514", "syslog://nohost", "syslog://h:514?format=json", "http://x.example"} {
		rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/notifications", "a-itadmin",
			map[string]any{"topic": "siem.audit", "kind": "syslog", "endpoint": bad}))
		if rec.Code < 400 {
			t.Fatalf("%q was accepted as a SIEM destination", bad)
		}
	}
}
