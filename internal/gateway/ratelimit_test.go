package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"platform/internal/command"
)

// T8: the plan's rate limit is the plan's, not the plan's times the
// number of gateways. Two instances over one database share one bucket.
func TestTheRateLimitIsSharedAcrossInstances(t *testing.T) {
	a := newFixture(t)
	adminExec(t, `UPDATE tenants SET api_rate_per_min = 3 WHERE id = $1`, tenantA)

	pipeB := command.New(command.NewDevKeyProvider(1024), command.ByOS{Fallback: okPush{}}, command.DefaultLimiter())
	b := New(Config{
		Directory: a.g.dir, Store: a.g.store, Signer: a.g.signer, Pipeline: pipeB, Identity: idp,
		CSRFKey: testKey, Sessions: a.sessions, Sealer: a.sealer, Enrol: a.enrol, Notify: a.notify,
		InsecureCookies: true,
	})
	onB := func() int {
		rec := httptest.NewRecorder()
		b.Handler().ServeHTTP(rec, req(t, "GET", hostA, "/api/devices", "a-super"))
		return rec.Code
	}

	// Two on A, one on B: three of three.
	for i := 0; i < 2; i++ {
		if rec, _ := do(t, a, req(t, "GET", hostA, "/api/devices", "a-super")); rec.Code != 200 {
			t.Fatalf("request %d on A: %d", i+1, rec.Code)
		}
	}
	if code := onB(); code != 200 {
		t.Fatalf("the first request on B: %d", code)
	}
	// The fourth, on either, is over the plan.
	if code := onB(); code != http.StatusTooManyRequests {
		t.Fatalf("instance B let a fourth request through: %d; the limit is per instance, not per plan", code)
	}
	if rec, _ := do(t, a, req(t, "GET", hostA, "/api/devices", "a-super")); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("instance A let a fifth request through: %d", rec.Code)
	}
	// Tenant B has a bucket of its own.
	if rec, _ := do(t, a, req(t, "GET", hostB, "/api/devices", "b-itadmin")); rec.Code != 200 {
		t.Fatalf("tenant B was limited by tenant A's plan: %d", rec.Code)
	}
}
