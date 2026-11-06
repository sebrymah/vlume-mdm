package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"platform/internal/command"
)

// F12: a lock in seconds. A device holding its queue open is handed the
// command the moment it is pushed, not at its next check-in.

func TestAHeldQueueReturnsTheMomentACommandIsPushed(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]
	cert := trustedCert(t, tenantA, dev)

	// No work: a short wait returns empty when it runs out.
	start := time.Now()
	r := req(t, "GET", hostA, "/api/my/commands?wait=1", "")
	r.TLS = cert
	rec, body := do(t, f, r)
	if rec.Code != 200 || len(body["commands"].([]any)) != 0 || time.Since(start) < 900*time.Millisecond {
		t.Fatalf("an empty wait: %d %v after %s", rec.Code, body, time.Since(start))
	}

	// Work arrives while the queue is held: the poll returns in well under
	// a second, with the fallback tick five seconds away.
	type result struct {
		body map[string]any
		took time.Duration
	}
	got := make(chan result, 1)
	go func() {
		r := req(t, "GET", hostA, "/api/my/commands?wait=20", "")
		r.TLS = cert
		began := time.Now()
		_, b := do(t, f, r)
		got <- result{b, time.Since(began)}
	}()
	time.Sleep(300 * time.Millisecond)
	pushed := time.Now()
	if rec, body := do(t, f, form(t, hostA, "/api/devices/"+dev.String()+"/lock", "a-itadmin",
		url.Values{"reason": {"left in a taxi"}})); rec.Code != http.StatusAccepted {
		t.Fatalf("lock: %d %v", rec.Code, body)
	}
	select {
	case res := <-got:
		cmds := res.body["commands"].([]any)
		if len(cmds) != 1 || cmds[0].(map[string]any)["type"] != "lock" {
			t.Fatalf("the held poll returned %v", res.body)
		}
		if since := time.Since(pushed); since > 2*time.Second {
			t.Fatalf("the lock took %s to reach the held poll; the wake did not fire", since)
		}
	case <-time.After(25 * time.Second):
		t.Fatal("the held poll never returned")
	}
}

// Behind a balancer the phone's held poll and the administrator's lock
// land on different instances. The wake has to cross: raised on the
// command's transaction, delivered by the database at commit, received by
// the instance holding the poll.
func TestALockRaisedOnOneInstanceReachesAPollHeldOnAnother(t *testing.T) {
	a := newFixture(t)
	dev := a.devices[tenantA][0]
	cert := trustedCert(t, tenantA, dev)

	// A second gateway over the same database, with a pipeline of its
	// own, as a second process would have. Only it listens: if the wake
	// reaches it, it crossed through the database and not through memory.
	pipeB := command.New(command.NewDevKeyProvider(1024), command.ByOS{Fallback: okPush{}}, command.DefaultLimiter())
	b := New(Config{
		Directory: a.g.dir, Store: a.g.store, Signer: a.g.signer, Pipeline: pipeB,
		CSRFKey: testKey, Sessions: a.sessions, Sealer: a.sealer, Enrol: a.enrol, Notify: a.notify,
		InsecureCookies: true,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.RunWake(ctx)
	time.Sleep(500 * time.Millisecond) // the listener's connection is up

	type result struct {
		body map[string]any
		took time.Duration
	}
	got := make(chan result, 1)
	go func() {
		r := req(t, "GET", hostA, "/api/my/commands?wait=20", "")
		r.TLS = cert
		began := time.Now()
		rec := httptest.NewRecorder()
		b.Handler().ServeHTTP(rec, r)
		var body map[string]any
		_ = json.NewDecoder(rec.Body).Decode(&body)
		got <- result{body, time.Since(began)}
	}()
	time.Sleep(300 * time.Millisecond)

	pushed := time.Now()
	if rec, body := do(t, a, form(t, hostA, "/api/devices/"+dev.String()+"/lock", "a-itadmin",
		url.Values{"reason": {"left on the bus"}})); rec.Code != http.StatusAccepted {
		t.Fatalf("lock on instance A: %d %v", rec.Code, body)
	}
	select {
	case res := <-got:
		cmds, _ := res.body["commands"].([]any)
		if len(cmds) != 1 || cmds[0].(map[string]any)["type"] != "lock" {
			t.Fatalf("the poll on instance B returned %v", res.body)
		}
		if since := time.Since(pushed); since > 2*time.Second {
			t.Fatalf("the lock took %s to cross to instance B; the shared wake did not fire", since)
		}
	case <-time.After(25 * time.Second):
		t.Fatal("the poll on instance B never returned")
	}
}
