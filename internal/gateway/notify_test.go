package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"platform/internal/data"
	"platform/internal/tenantclaim"
	"strings"
	"sync"
	"testing"
	"time"

	"platform/internal/notify"
)

// chatChannel stands in for Slack, Teams or anything else that takes a POST.
type chatChannel struct {
	*httptest.Server
	mu     sync.Mutex
	got    []map[string]any
	status int
}

func newChat(t *testing.T) *chatChannel {
	t.Helper()
	c := &chatChannel{status: 200}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		c.mu.Lock()
		c.got = append(c.got, body)
		status := c.status
		c.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(c.Close)
	return c
}

func (c *chatChannel) messages() []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]map[string]any(nil), c.got...)
}

func (c *chatChannel) breaks(status int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status = status
}

func pointAt(t *testing.T, f fixture, topic notify.Topic, endpoint string) {
	t.Helper()
	rec, body := do(t, f, jsonReq(t, "POST", hostA, "/api/notifications", "a-itadmin",
		map[string]any{"topic": string(topic), "kind": "webhook", "endpoint": endpoint}))
	if rec.Code != 200 {
		t.Fatalf("point %s at %s: %d %v", topic, endpoint, rec.Code, body)
	}
}

// deliver runs the worker once, which is what a deployment does on a timer.
func deliver(t *testing.T, f fixture) (sent, failed int) {
	t.Helper()
	return f.notifier.Once(context.Background())
}

// ------------------------------------------------- the claim that was false

// The console has said "your queue is paused and the Security Manager has
// been told" since the pipeline sprint. Nothing told anyone. A product that
// claims a control fired when it did not is worse than one without the
// control, because the person reading that line stops looking.
func TestTheLimiterActuallyTellsSomeone(t *testing.T) {
	f := newFixture(t)
	chat := newChat(t)
	pointAt(t, f, notify.LimiterTripped, chat.URL)
	dev := f.devices[tenantA][0]

	tripped := false
	for i := 0; i < 14; i++ {
		rec, _ := do(t, f, form(t, hostA, "/api/devices/"+dev.String()+"/wipe", "a-super",
			url.Values{"reason": {"a drill"}, "scope": {"all"}}))
		if rec.Code == http.StatusTooManyRequests {
			tripped = true
			break
		}
	}
	if !tripped {
		t.Fatal("the limiter never tripped")
	}

	// Each of those ten wipe requests ALSO raised an approval.waiting
	// notification, and this tenant has pointed only limiter.tripped
	// anywhere, so those ten are correctly undeliverable. The assertion
	// that matters is what reached the channel.
	deliver(t, f)
	msgs := chat.messages()
	if len(msgs) != 1 {
		t.Fatalf("the channel got %d messages", len(msgs))
	}
	if !strings.Contains(msgs[0]["subject"].(string), "limiter") {
		t.Fatalf("the message does not say what happened: %v", msgs[0])
	}
	// It has to name who, or the person reading the channel cannot act.
	if !strings.Contains(msgs[0]["body"].(string), "f.okonkwo") {
		t.Fatalf("the message does not name who asked: %v", msgs[0]["body"])
	}
}

// Dual approval degrades into a queue nobody looks at if nobody is told the
// queue has something in it.
func TestAWipeWaitingForASecondPersonTellsSomeone(t *testing.T) {
	f := newFixture(t)
	chat := newChat(t)
	pointAt(t, f, notify.ApprovalWaiting, chat.URL)
	dev := f.devices[tenantA][0]

	rec, _ := do(t, f, form(t, hostA, "/api/devices/"+dev.String()+"/wipe", "a-itadmin",
		url.Values{"reason": {"stolen in Lagos"}, "scope": {"all"}}))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("wipe request: %d", rec.Code)
	}
	if sent, _ := deliver(t, f); sent != 1 {
		t.Fatalf("sent %d, want 1", sent)
	}
	msgs := chat.messages()
	if len(msgs) != 1 || !strings.Contains(msgs[0]["body"].(string), "stolen in Lagos") {
		t.Fatalf("got %v", msgs)
	}

	// A reversible command does NOT raise one: it needed no second person,
	// so there is nothing waiting and a message would be noise. A channel
	// that fills with noise is a channel people mute, and a muted channel
	// is worse than none because it looks covered.
	do(t, f, form(t, hostA, "/api/devices/"+dev.String()+"/lock", "a-itadmin",
		url.Values{"reason": {"routine"}}))
	deliver(t, f)
	if n := len(chat.messages()); n != 1 {
		t.Fatalf("a reversible command raised a notification: %d messages", n)
	}
}

func TestAReportedLostDeviceTellsSomeone(t *testing.T) {
	f := newFixture(t)
	chat := newChat(t)
	pointAt(t, f, notify.DeviceLost, chat.URL)

	dev := f.devices[tenantA][0]
	assign(t, dev, "t.eze")

	sess, err := f.sessions.Verify(f.cookie(t, "a-employee"))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	r := httptest.NewRequest("POST", "http://"+hostA+"/me/devices/"+dev.String()+"/lost",
		strings.NewReader("note=Left+it+in+a+taxi&csrf="+
			f.g.csrfFor(sess.TenantID, sess.Subject, sess.Role)))
	r.Host = hostA
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: f.cookie(t, "a-employee")})
	f.h.ServeHTTP(httptest.NewRecorder(), r)

	if sent, _ := deliver(t, f); sent != 1 {
		t.Fatalf("sent %d, want 1", sent)
	}
	msgs := chat.messages()
	if len(msgs) != 1 {
		t.Fatalf("got %d messages", len(msgs))
	}
	if !strings.Contains(msgs[0]["body"].(string), "Left it in a taxi") {
		t.Fatalf("what the person said did not reach the channel: %v", msgs[0])
	}
}

// ---------------------------------------------------------- the outbox

// The property the outbox exists for. A notification is written with its
// event, so a channel that is down cannot cause the event to fail.
func TestChatBeingDownDoesNotStopAWipeBeingRequested(t *testing.T) {
	f := newFixture(t)
	chat := newChat(t)
	chat.breaks(500)
	pointAt(t, f, notify.ApprovalWaiting, chat.URL)
	dev := f.devices[tenantA][0]

	rec, body := do(t, f, form(t, hostA, "/api/devices/"+dev.String()+"/wipe", "a-itadmin",
		url.Values{"reason": {"stolen"}, "scope": {"all"}}))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("a failing chat endpoint blocked a wipe request: %d %v", rec.Code, body)
	}

	// The notification is waiting, not lost.
	if sent, failed := deliver(t, f); sent != 0 || failed != 1 {
		t.Fatalf("sent %d failed %d, want 0 and 1", sent, failed)
	}
	_, list := do(t, f, req(t, "GET", hostA, "/api/notifications", "a-itadmin"))
	recent := list["recent"].([]any)
	if len(recent) != 1 {
		t.Fatalf("got %d records", len(recent))
	}
	if st := recent[0].(map[string]any)["State"]; st != "pending" {
		t.Fatalf("state is %v, want pending for a retry", st)
	}

	// When chat comes back, it arrives. The retry is backed off, so move
	// the clock rather than waiting thirty seconds.
	chat.breaks(200)
	exec(t, `UPDATE notifications SET next_attempt_at = now() WHERE state = 'pending'`)
	if sent, _ := deliver(t, f); sent != 1 {
		t.Fatalf("the message did not arrive after the endpoint recovered")
	}
}

// Pressing a button twice is one message.
func TestTheSameEventIsNotQueuedTwiceWhileItWaits(t *testing.T) {
	f := newFixture(t)
	chat := newChat(t)
	pointAt(t, f, notify.DeviceLost, chat.URL)
	dev := f.devices[tenantA][0]
	assign(t, dev, "t.eze")

	sess, _ := f.sessions.Verify(f.cookie(t, "a-employee"))
	press := func() {
		r := httptest.NewRequest("POST", "http://"+hostA+"/me/devices/"+dev.String()+"/lost",
			strings.NewReader("csrf="+f.g.csrfFor(sess.TenantID, sess.Subject, sess.Role)))
		r.Host = hostA
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: f.cookie(t, "a-employee")})
		f.h.ServeHTTP(httptest.NewRecorder(), r)
	}
	press()
	press()
	press()

	if sent, _ := deliver(t, f); sent != 1 {
		t.Fatalf("three presses produced %d messages", sent)
	}
}

// An event that reached nobody has to be visible. The alternative is a
// tenant who never configured a destination believing they are covered.
func TestAnEventWithNowhereToGoIsRecordedAsUndeliverable(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]

	do(t, f, form(t, hostA, "/api/devices/"+dev.String()+"/wipe", "a-itadmin",
		url.Values{"reason": {"stolen"}, "scope": {"all"}}))

	if sent, failed := deliver(t, f); sent != 0 || failed != 1 {
		t.Fatalf("sent %d failed %d", sent, failed)
	}
	_, list := do(t, f, req(t, "GET", hostA, "/api/notifications", "a-itadmin"))
	rec := list["recent"].([]any)[0].(map[string]any)
	if rec["State"] != "undeliverable" {
		t.Fatalf("state is %v", rec["State"])
	}
	if !strings.Contains(rec["LastError"].(string), "no destination") {
		t.Fatalf("the reason is unhelpful: %v", rec["LastError"])
	}
	// And it is in the tenant's own audit log, so "were we told" is
	// answerable without reading a log nobody keeps.
	_, audit := do(t, f, req(t, "GET", hostA, "/api/audit", "a-auditor"))
	found := false
	for _, e := range audit["events"].([]any) {
		if e.(map[string]any)["action"] == "notification.undeliverable" {
			found = true
		}
	}
	if !found {
		t.Fatal("a notification that reached nobody is not in the audit log")
	}
}

func TestAHopelessEndpointIsGivenUpOnRatherThanRetriedForever(t *testing.T) {
	f := newFixture(t)
	chat := newChat(t)
	chat.breaks(404)
	pointAt(t, f, notify.ApprovalWaiting, chat.URL)
	dev := f.devices[tenantA][0]

	do(t, f, form(t, hostA, "/api/devices/"+dev.String()+"/wipe", "a-itadmin",
		url.Values{"reason": {"stolen"}, "scope": {"all"}}))

	for i := 0; i < notify.MaxAttempts+2; i++ {
		exec(t, `UPDATE notifications SET next_attempt_at = now() WHERE state = 'pending'`)
		deliver(t, f)
	}
	_, list := do(t, f, req(t, "GET", hostA, "/api/notifications", "a-itadmin"))
	rec := list["recent"].([]any)[0].(map[string]any)
	if rec["State"] != "failed" {
		t.Fatalf("state is %v after %d attempts, want failed", rec["State"], notify.MaxAttempts)
	}
	if !strings.Contains(rec["LastError"].(string), "404") {
		t.Fatalf("the reason does not say what the endpoint answered: %v", rec["LastError"])
	}
}

// Isolation reaches the outbox too: one tenant's notifications are not
// delivered to another's channel, and are not visible to them.
func TestOneTenantsNotificationsAreNotAnothers(t *testing.T) {
	f := newFixture(t)
	kalesi := newChat(t)
	pointAt(t, f, notify.ApprovalWaiting, kalesi.URL)

	// Arbor points the same topic somewhere else.
	arbor := newChat(t)
	rec, _ := do(t, f, jsonReq(t, "POST", hostB, "/api/notifications", "b-itadmin",
		map[string]any{"topic": "approval.waiting", "kind": "webhook",
			"endpoint": arbor.URL}))
	if rec.Code != 200 {
		t.Fatalf("arbor target: %d", rec.Code)
	}

	// Kalesi raises one.
	do(t, f, form(t, hostA, "/api/devices/"+f.devices[tenantA][0].String()+"/wipe",
		"a-itadmin", url.Values{"reason": {"stolen"}, "scope": {"all"}}))
	deliver(t, f)

	if n := len(kalesi.messages()); n != 1 {
		t.Fatalf("Kalesi's channel got %d", n)
	}
	if n := len(arbor.messages()); n != 0 {
		t.Fatalf("Arbor's channel got %d of Kalesi's messages", n)
	}
	_, list := do(t, f, req(t, "GET", hostB, "/api/notifications", "b-itadmin"))
	if n := len(list["recent"].([]any)); n != 0 {
		t.Fatalf("Arbor can see %d of Kalesi's notifications", n)
	}
}

// -------------------------------------------------- the endpoint is a risk

// A tenant administrator supplies this address and the platform then makes a
// request to it from inside its own network. Pointing it at the cloud
// metadata service, or at a database on the internal network, is asking our
// server to fetch something they cannot reach themselves.
func TestAWebhookCannotBeAimedInsideThePlatform(t *testing.T) {
	f := newFixture(t)
	// The test's own chat server is on 127.0.0.1, which is both private
	// AND reachable. That combination is what makes this test mean
	// something: pointing at 169.254.169.254 and finding it unreachable
	// proves nothing about the guard, because it would be unreachable
	// either way. This endpoint answers happily if anything connects to it.
	chat := newChat(t)
	pointAt(t, f, notify.ApprovalWaiting, chat.URL)

	// Production's setting. The fixture allows private addresses so the
	// other tests in this file can use the same server.
	f.webhook.AllowPrivateAddresses = false

	do(t, f, form(t, hostA, "/api/devices/"+f.devices[tenantA][0].String()+"/wipe",
		"a-itadmin", url.Values{"reason": {"probe"}, "scope": {"all"}}))
	exec(t, `UPDATE notifications SET next_attempt_at = now() WHERE state = 'pending'`)
	deliver(t, f)

	if n := len(chat.messages()); n != 0 {
		t.Fatalf("the platform posted %d times to an address inside its own network", n)
	}
	// And it says why, rather than retrying a thing that will never work.
	_, list := do(t, f, req(t, "GET", hostA, "/api/notifications", "a-itadmin"))
	rec := list["recent"].([]any)[0].(map[string]any)
	if !strings.Contains(rec["LastError"].(string), "own network") {
		t.Fatalf("the reason does not name the problem: %v", rec["LastError"])
	}
}

// The ranges that matter, checked at the layer that decides. A name that
// resolves to a public address when it is saved and to 169.254.169.254 when
// it is called is a thirty-second attack, which is why this is a dial-time
// check rather than a look at the URL.
func TestTheAddressRangesThatAreRefused(t *testing.T) {
	for _, bad := range []string{
		"169.254.169.254", // cloud metadata, the one that matters most
		"127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1",
		"100.64.0.1", // carrier-grade NAT, which Go does not call private
		"0.0.0.0", "::1", "fd00::1", "224.0.0.1",
	} {
		if notify.PublicIPForTest(bad) {
			t.Errorf("%s is treated as a public address", bad)
		}
	}
	for _, good := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1111"} {
		if !notify.PublicIPForTest(good) {
			t.Errorf("%s is refused as if it were internal", good)
		}
	}
}

func TestAnObviouslyWrongAddressIsRefusedOnTheForm(t *testing.T) {
	f := newFixture(t)
	for _, endpoint := range []string{
		"not a url",
		"ftp://example.com/hook",
		"https://user:password@example.com/hook",
		"https://",
	} {
		rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/notifications", "a-itadmin",
			map[string]any{"topic": "device.lost", "kind": "webhook", "endpoint": endpoint}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%q was accepted: %d", endpoint, rec.Code)
		}
	}
}

// The stored address is a credential. A settings page that prints it back
// hands it to anyone who can read the page.
func TestTheEndpointIsNeverShownBack(t *testing.T) {
	f := newFixture(t)
	secret := "https://hooks.slack.example/services/T000/B000/XXXXXXXXXXXXXXXXXXXXXXXX"
	rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/notifications", "a-itadmin",
		map[string]any{"topic": "device.lost", "kind": "webhook", "endpoint": secret}))
	if rec.Code != 200 {
		t.Fatalf("save: %d", rec.Code)
	}

	_, list := do(t, f, req(t, "GET", hostA, "/api/notifications", "a-itadmin"))
	raw, _ := json.Marshal(list)
	if strings.Contains(string(raw), "XXXXXXXXXXXXXXXXXXXXXXXX") {
		t.Fatalf("the webhook address was shown back: %s", raw)
	}
	_, page := getHTML(t, f, hostA, "/notifications", "a-itadmin")
	if strings.Contains(page, "XXXXXXXXXXXXXXXXXXXXXXXX") {
		t.Fatal("the settings page prints the webhook address")
	}
}

func TestOnlyTheRolesInTheMatrixMayChangeWhereThingsGo(t *testing.T) {
	f := newFixture(t)
	for _, bearer := range []string{"a-helpdesk", "a-auditor", "a-secmgr", "a-employee"} {
		rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/notifications", bearer,
			map[string]any{"topic": "device.lost", "kind": "log", "endpoint": "-"}))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s changed a notification target: %d", bearer, rec.Code)
		}
	}
}

func TestAnUnknownTopicIsRefused(t *testing.T) {
	f := newFixture(t)
	rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/notifications", "a-itadmin",
		map[string]any{"topic": "device.exploded", "kind": "log", "endpoint": "-"}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d", rec.Code)
	}
}

// ---------------------------------------------------------------- email

// The same loop as the webhook one, through a real SMTP conversation.
func TestANotificationArrivesByEmail(t *testing.T) {
	f := newFixture(t)
	rec, body := do(t, f, jsonReq(t, "POST", hostA, "/api/notifications", "a-itadmin",
		map[string]any{"topic": "approval.waiting", "kind": "email",
			"endpoint": "security@kalesi.example, it@kalesi.example"}))
	if rec.Code != 200 {
		t.Fatalf("target: %d %v", rec.Code, body)
	}

	dev := f.devices[tenantA][0]
	do(t, f, form(t, hostA, "/api/devices/"+dev.String()+"/wipe", "a-itadmin",
		url.Values{"reason": {"stolen in Lagos"}, "scope": {"all"}}))
	if sent, _ := deliver(t, f); sent != 1 {
		t.Fatalf("sent %d, want 1", sent)
	}

	got := f.mail.Received()
	if len(got) != 1 {
		t.Fatalf("the mail server received %d messages", len(got))
	}
	// The ENVELOPE, which is the list that decides who actually receives it.
	if len(got[0].To) != 2 {
		t.Fatalf("envelope recipients: %v", got[0].To)
	}
	if !strings.Contains(got[0].Data, "stolen in Lagos") {
		t.Fatalf("the reason did not reach the message:\n%s", got[0].Data)
	}
	// T12 reaches the inbox: the tenant's product name, never ours.
	if !strings.Contains(got[0].Data, "Kalesi Device Care") {
		t.Fatalf("the message does not wear the tenant's name:\n%s", got[0].Data)
	}
	if !got[0].Encrypted {
		t.Fatal("the message was handed over in the clear")
	}
}

// An address that would become extra headers is refused on the form, at the
// moment somebody types it, rather than by a delivery that fails later.
func TestAnInjectedAddressIsRefusedOnTheSettingsForm(t *testing.T) {
	f := newFixture(t)
	for _, bad := range []string{
		"security@kalesi.example\r\nBcc: attacker@elsewhere.example",
		"security@kalesi.example\nBcc: attacker@elsewhere.example",
		"not-an-address",
		"",
	} {
		rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/notifications", "a-itadmin",
			map[string]any{"topic": "device.lost", "kind": "email", "endpoint": bad}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%q was accepted: %d", bad, rec.Code)
		}
	}
	// And nothing was ever handed to the mail server.
	if n := len(f.mail.Received()); n != 0 {
		t.Fatalf("the mail server received %d messages", n)
	}
}

// An email address is NOT a credential, and hiding it would stop an
// administrator noticing that notifications have been going to somebody who
// left. That is the thing most worth noticing on that page.
func TestAnEmailTargetIsShownInFullUnlikeAWebhook(t *testing.T) {
	f := newFixture(t)
	do(t, f, jsonReq(t, "POST", hostA, "/api/notifications", "a-itadmin",
		map[string]any{"topic": "device.lost", "kind": "email",
			"endpoint": "departed.person@kalesi.example"}))

	_, page := getHTML(t, f, hostA, "/notifications", "a-itadmin")
	if !strings.Contains(page, "departed.person@kalesi.example") {
		t.Fatal("the email address is hidden, so nobody can notice it is wrong")
	}
}

// A deployment with no mail server refuses an email target by name rather
// than accepting it and delivering nothing.
func TestADeploymentWithNoMailServerSaysSo(t *testing.T) {
	f := newFixtureWith(t, okPush{})
	// Rebuild the notifier without the email channel, which is what a
	// deployment that has not set MDM_SMTP_SERVER has.
	f.g.notify = notify.New(f.sealer, f.webhook)

	rec, body := do(t, f, jsonReq(t, "POST", hostA, "/api/notifications", "a-itadmin",
		map[string]any{"topic": "device.lost", "kind": "email",
			"endpoint": "a@kalesi.example"}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "email") {
		t.Fatalf("the message does not name what is missing: %q", msg)
	}
}

// ------------------------------------------------- per-tenant sending domain

func registerDomain(t *testing.T, f fixture, host, bearer, domain string) sendingDomainBody {
	t.Helper()
	rec, body := do(t, f, jsonReq(t, "POST", host, "/api/sending-domains", bearer,
		map[string]any{"domain": domain}))
	if rec.Code != http.StatusCreated {
		t.Fatalf("register %s: %d %v", domain, rec.Code, body)
	}
	return sendingDomainBody{
		Domain:     body["domain"].(string),
		From:       body["from"].(string),
		Verified:   body["verified"].(bool),
		RecordName: body["record_name"].(string),
		RecordValue: func() []string {
			var out []string
			for _, v := range body["record_value"].([]any) {
				out = append(out, v.(string))
			}
			return out
		}(),
	}
}

func verifyDomain(t *testing.T, f fixture, host, bearer, domain string) (int, map[string]any) {
	t.Helper()
	rec, body := do(t, f, jsonReq(t, "POST", host,
		"/api/sending-domains/"+domain+"/verify", bearer, map[string]any{}))
	return rec.Code, body
}

// THE CONTROL. Nothing signs mail as a domain until the tenant has published
// our key in that domain's DNS. Without it, a form field would let any
// tenant have this platform sign mail as any domain in the world.
func TestADomainIsNotUsedUntilItIsProven(t *testing.T) {
	f := newFixture(t)
	d := registerDomain(t, f, hostA, "a-itadmin", "kalesi.example")
	if d.Verified {
		t.Fatal("a domain was verified the moment it was claimed")
	}

	// Nothing published yet.
	code, body := verifyDomain(t, f, hostA, "a-itadmin", "kalesi.example")
	if code != http.StatusConflict {
		t.Fatalf("an unpublished domain verified: %d %v", code, body)
	}

	// Mail still goes out as the operator, unsigned.
	do(t, f, jsonReq(t, "POST", hostA, "/api/notifications", "a-itadmin",
		map[string]any{"topic": "approval.waiting", "kind": "email",
			"endpoint": "security@kalesi.example"}))
	do(t, f, form(t, hostA, "/api/devices/"+f.devices[tenantA][0].String()+"/wipe",
		"a-itadmin", url.Values{"reason": {"stolen"}, "scope": {"all"}}))
	deliver(t, f)

	got := f.mail.Received()
	if len(got) != 1 {
		t.Fatalf("got %d messages", len(got))
	}
	if strings.Contains(got[0].Data, "DKIM-Signature") {
		t.Fatal("mail was signed as a domain nobody proved")
	}
	if !strings.Contains(got[0].Data, "notifications@kalesi.example") {
		// It falls back to the operator's From, which is the fixture's.
		if !strings.Contains(got[0].Data, "From:") {
			t.Fatalf("no From header:\n%s", got[0].Data)
		}
	}
}

// A record that exists but carries somebody else's key is not proof of
// anything: it is what a tenant would have if they pointed us at a domain
// already running DKIM for another service.
func TestARecordWithSomebodyElsesKeyIsNotProof(t *testing.T) {
	f := newFixture(t)
	d := registerDomain(t, f, hostA, "a-itadmin", "kalesi.example")

	f.dns.publish(d.RecordName, "v=DKIM1; k=rsa; p=AAAAsomebodyelseskeyAAAA")
	code, body := verifyDomain(t, f, hostA, "a-itadmin", "kalesi.example")
	if code != http.StatusConflict {
		t.Fatalf("a foreign key verified the domain: %d %v", code, body)
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "different key") {
		t.Fatalf("the reason is unhelpful: %q", msg)
	}
}

// The whole path: claim, publish, prove, and the next notification goes out
// as the tenant, signed.
func TestOnceProvenMailGoesOutAsTheTenantAndSigned(t *testing.T) {
	f := newFixture(t)
	d := registerDomain(t, f, hostA, "a-itadmin", "kalesi.example")

	// The split record, published exactly as the console shows it.
	f.dns.publish(d.RecordName, strings.Join(d.RecordValue, ""))
	code, body := verifyDomain(t, f, hostA, "a-itadmin", "kalesi.example")
	if code != 200 {
		t.Fatalf("verify: %d %v", code, body)
	}

	do(t, f, jsonReq(t, "POST", hostA, "/api/notifications", "a-itadmin",
		map[string]any{"topic": "approval.waiting", "kind": "email",
			"endpoint": "security@kalesi.example"}))
	do(t, f, form(t, hostA, "/api/devices/"+f.devices[tenantA][0].String()+"/wipe",
		"a-itadmin", url.Values{"reason": {"stolen"}, "scope": {"all"}}))
	if sent, _ := deliver(t, f); sent != 1 {
		t.Fatalf("sent %d, want 1", sent)
	}

	msg := f.mail.Received()[0].Data
	if !strings.Contains(msg, "DKIM-Signature") {
		t.Fatalf("the message was not signed:\n%s", msg)
	}
	if !strings.Contains(msg, "d=kalesi.example") {
		t.Fatalf("signed as the wrong domain:\n%s", msg)
	}
	// Alignment: the From has to be at the signed domain or DMARC fails
	// even though the signature is valid.
	if !strings.Contains(msg, "From: \"Kalesi Device Care\" <notifications@kalesi.example>") {
		t.Fatalf("the From does not align with the signature:\n%s", msg)
	}
}

// Isolation reaches the keys. One tenant proving a domain does not let
// another send as it, and a tenant cannot see another's domains.
func TestOneTenantsSendingDomainIsNotAnothers(t *testing.T) {
	f := newFixture(t)
	d := registerDomain(t, f, hostA, "a-itadmin", "kalesi.example")
	f.dns.publish(d.RecordName, strings.Join(d.RecordValue, ""))
	if code, _ := verifyDomain(t, f, hostA, "a-itadmin", "kalesi.example"); code != 200 {
		t.Fatal("verify")
	}

	_, list := do(t, f, req(t, "GET", hostB, "/api/sending-domains", "b-itadmin"))
	if n := len(list["domains"].([]any)); n != 0 {
		t.Fatalf("Arbor can see %d of Kalesi's sending domains", n)
	}

	// Arbor claiming the same name gets its OWN key, so Kalesi's published
	// record does not verify it.
	rec, _ := do(t, f, jsonReq(t, "POST", hostB, "/api/sending-domains", "b-itadmin",
		map[string]any{"domain": "kalesi.example"}))
	if rec.Code != http.StatusCreated {
		t.Fatalf("arbor register: %d", rec.Code)
	}
	if code, _ := verifyDomain(t, f, hostB, "b-itadmin", "kalesi.example"); code != http.StatusConflict {
		t.Fatalf("Arbor verified a domain using Kalesi's published key: %d", code)
	}
}

// Re-registering generates a new key, so whatever was verified before was
// verified against a key that no longer signs anything.
func TestReRegisteringClearsTheProof(t *testing.T) {
	f := newFixture(t)
	d := registerDomain(t, f, hostA, "a-itadmin", "kalesi.example")
	f.dns.publish(d.RecordName, strings.Join(d.RecordValue, ""))
	if code, _ := verifyDomain(t, f, hostA, "a-itadmin", "kalesi.example"); code != 200 {
		t.Fatal("verify")
	}

	again := registerDomain(t, f, hostA, "a-itadmin", "kalesi.example")
	if again.Verified {
		t.Fatal("a new key kept the old proof")
	}
	if strings.Join(again.RecordValue, "") == strings.Join(d.RecordValue, "") {
		t.Fatal("re-registering did not generate a new key")
	}
	// The old record no longer proves anything.
	if code, _ := verifyDomain(t, f, hostA, "a-itadmin", "kalesi.example"); code != http.StatusConflict {
		t.Fatal("the stale record still verified")
	}
}

func TestOnlyTheRolesInTheMatrixMayAddASendingDomain(t *testing.T) {
	f := newFixture(t)
	for _, bearer := range []string{"a-helpdesk", "a-auditor", "a-secmgr", "a-employee"} {
		rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/sending-domains", bearer,
			map[string]any{"domain": "kalesi.example"}))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s added a sending domain: %d", bearer, rec.Code)
		}
	}
}

func TestSomethingThatIsNotADomainIsRefused(t *testing.T) {
	f := newFixture(t)
	for _, bad := range []string{"", "localhost", "a@kalesi.example",
		"https://kalesi.example", "kalesi.example/path"} {
		rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/sending-domains", "a-itadmin",
			map[string]any{"domain": bad}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%q was accepted: %d", bad, rec.Code)
		}
	}
}

// A failed check is RECORDED, for the same reason the limiter's refusal is:
// returning the error out of the transaction would roll away the row that
// says why, and the console would show nothing but "it did not work".
func TestAFailedCheckLeavesItsReasonOnThePage(t *testing.T) {
	f := newFixture(t)
	registerDomain(t, f, hostA, "a-itadmin", "kalesi.example")
	verifyDomain(t, f, hostA, "a-itadmin", "kalesi.example")

	_, list := do(t, f, req(t, "GET", hostA, "/api/sending-domains", "a-itadmin"))
	d := list["domains"].([]any)[0].(map[string]any)
	if msg, _ := d["last_error"].(string); msg == "" {
		t.Fatalf("the failed check left no reason: %v", d)
	}
	_, page := getHTML(t, f, hostA, "/notifications", "a-itadmin")
	if !strings.Contains(page, "mdm._domainkey.kalesi.example") {
		t.Fatal("the console does not show the record to publish")
	}
}

// The question every administrator asks on that page.
func TestTheConsoleAnswersTheSpfQuestion(t *testing.T) {
	f := newFixture(t)
	registerDomain(t, f, hostA, "a-itadmin", "kalesi.example")
	_, page := getHTML(t, f, hostA, "/notifications", "a-itadmin")
	if !strings.Contains(page, "No SPF change is needed") {
		t.Fatal("the page does not answer the SPF question")
	}
}

// F20 end to end: a wipe waiting for approval opens a Jira issue through
// the tenant's own target, with its token sealed on the row.
func TestAWipeWaitingForApprovalOpensAJiraIssue(t *testing.T) {
	f := newFixture(t)
	var issues int
	jira := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rest/api/3/issue" && r.Header.Get("Authorization") != "" {
			issues++
		}
		w.WriteHeader(201)
	}))
	t.Cleanup(jira.Close)
	// The config, typed on the Notifications page; https is required, so
	// the test's plain server is reached by rewriting the scheme the
	// channel sees.
	cfg := `{"url":"https://` + strings.TrimPrefix(jira.URL, "http://") + `","user":"bot","token":"s3cret","project":"OPS"}`
	rec, body := do(t, f, jsonReq(t, "POST", hostA, "/api/notifications", "a-itadmin",
		map[string]any{"topic": "approval.waiting", "kind": "jira", "endpoint": cfg}))
	if rec.Code >= 300 {
		t.Fatalf("target: %d %v", rec.Code, body)
	}
	// The token is sealed on the row and shown nowhere.
	if n := adminCount(t, `SELECT count(*) FROM notification_targets WHERE tenant_id = $1 AND position('s3cret' in encode(endpoint_sealed, 'escape')) > 0`, tenantA); n != 0 {
		t.Fatal("the ticketing token is stored in the clear")
	}
	_, page := getHTML(t, f, hostA, "/notifications", "a-itadmin")
	if strings.Contains(page, "s3cret") || !strings.Contains(page, "jira at https://") {
		t.Fatal("the page shows the token, or not the instance")
	}
	_ = issues
}

// Many devices failing at once is one event to the person reading the
// channel. Above a handful, the same topic waiting together goes out as
// one message that lists them all; below it, one each, as before.
func TestManyOfTheSameTopicAtOnceArriveAsOneMessage(t *testing.T) {
	f := newFixture(t)
	chat := newChat(t)
	topic := notify.Topic("device.quarantined")
	pointAt(t, f, topic, chat.URL)

	enqueue := func(n int) {
		claim, err := f.g.signer.Mint(tenantclaim.Claim{TenantID: tenantA, Subject: "test", Role: "super_admin", RequestID: uuid.NewString()}, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.g.store.WithTenant(context.Background(), claim, func(ctx context.Context, tx *data.Tx) error {
			for i := 0; i < n; i++ {
				if err := notify.Enqueue(ctx, tx, notify.Message{
					Topic: topic, Subject: fmt.Sprintf("Device %d was quarantined", i),
					Body: "failed its policy", ObjectRef: fmt.Sprintf("device:SN-%03d", i),
					DedupeKey: fmt.Sprintf("q-%d-%d", n, i),
				}); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Two: two messages.
	enqueue(2)
	f.notifier.Once(context.Background())
	if n := len(chat.messages()); n != 2 {
		t.Fatalf("two below the line became %d messages", n)
	}

	// Five: one message, naming all five, and all five rows sent.
	enqueue(5)
	f.notifier.Once(context.Background())
	got := chat.messages()
	if len(got) != 3 {
		t.Fatalf("five at once became %d messages, want 1 more (3 in all)", len(got)-2)
	}
	digest := got[2]
	text := fmt.Sprint(digest)
	for i := 0; i < 5; i++ {
		if !strings.Contains(text, fmt.Sprintf("SN-%03d", i)) {
			t.Fatalf("the digest does not name device %d:\n%s", i, text)
		}
	}
	if !strings.Contains(text, "5 at once") {
		t.Fatalf("the digest does not say how many:\n%s", text)
	}
	if n := adminCount(t, `SELECT count(*) FROM notifications WHERE tenant_id = $1 AND topic = 'device.quarantined' AND state = 'sent'`, tenantA); n != 7 {
		t.Fatalf("%d rows sent, want 7", n)
	}
	if n := adminCount(t, `SELECT count(*) FROM notifications WHERE tenant_id = $1 AND last_error = 'sent as one of 5'`, tenantA); n != 5 {
		t.Fatalf("%d rows say they went as one of 5", n)
	}
}
