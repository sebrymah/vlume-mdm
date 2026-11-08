package gateway

import (
	"context"
	"encoding/json"
	"os"

	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"platform/internal/qr/qrtest"
)

// Join links (0046): a link anyone can open, a code sent by another route, a
// limit on devices and on time. Every rule is a test here and a control in
// run_go.sh.

var (
	joinLinkRE = regexp.MustCompile(`id="join-link" readonly value="([^"]+)"`)
	joinCodeRE = regexp.MustCompile(`id="join-code" readonly value="(\d{6})"`)
)

// makeJoin makes a link as an administrator and returns its path and code.
func makeJoin(t *testing.T, f fixture, vals url.Values) (path, code string) {
	t.Helper()
	rec := postForm(t, f, "a-itadmin", "/android/join", vals)
	body := rec.Body.String()
	l, c := joinLinkRE.FindStringSubmatch(body), joinCodeRE.FindStringSubmatch(body)
	if rec.Code != 200 || l == nil || c == nil {
		t.Fatalf("making a join link: %d %q\n%.500s", rec.Code, said(rec), body)
	}
	u, err := url.Parse(l[1])
	if err != nil || u.Host != hostA {
		t.Fatalf("the link is not on this organisation's host: %q", l[1])
	}
	return u.Path, c[1]
}

func joinForm(name string, uses, hours string, ownership string) url.Values {
	return url.Values{"name": {name}, "uses": {uses}, "hours": {hours}, "ownership": {ownership}}
}

// open is somebody with no account and no session at all.
func open(t *testing.T, f fixture, method, host, path string, vals url.Values, ua string) *httptest.ResponseRecorder {
	t.Helper()
	var body *strings.Reader
	if vals != nil {
		body = strings.NewReader(vals.Encode())
	} else {
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, "http://"+host+path, body)
	r.Host = host
	r.RemoteAddr = "203.0.113.7:4000"
	if vals != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if ua != "" {
		r.Header.Set("User-Agent", ua)
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	return rec
}

func enter(t *testing.T, f fixture, path, code string) *httptest.ResponseRecorder {
	t.Helper()
	return open(t, f, "POST", hostA, path, url.Values{"code": {code}}, desktopUA)
}

func wrongCode(code string) string {
	if code == "000000" {
		return "000001"
	}
	return "000000"
}

func tokensIssued(f fixture) int { return len(f.google.TokenUsage) }

func queryString(t *testing.T, sql string, dst *string) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)
	if err := conn.QueryRow(ctx, sql).Scan(dst); err != nil {
		t.Fatalf("query: %v", err)
	}
}

func TestAJoinLinkOpensWithoutSigningInAndNeedsItsCode(t *testing.T) {
	f := selfReady(t)
	path, code := makeJoin(t, f, joinForm("Kemi's phone", "1", "168", "personal"))
	issued := tokensIssued(f)

	// Anyone can open it, with no account, and it gives nothing away yet.
	rec := open(t, f, "GET", hostA, path, nil, desktopUA)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "six-digit code") {
		t.Fatalf("opening the link: %d\n%.300s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "enterprise.google.com") || len(qrtest.PageImages(rec.Body.String())) != 0 {
		t.Fatal("the page gave a way in before the code was entered")
	}
	if rec.Header().Get("Referrer-Policy") != "no-referrer" || !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") {
		t.Fatal("the page that holds the secret in its address can be cached or leaked in a Referer")
	}

	// A wrong code reveals nothing and is counted.
	rec = enter(t, f, path, wrongCode(code))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "not right") {
		t.Fatalf("a wrong code: %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "enterprise.google.com") || tokensIssued(f) != issued {
		t.Fatal("a wrong code produced a way in")
	}
	if n := adminCount(t, `SELECT failed_count FROM join_links`); n != 1 {
		t.Fatalf("%d wrong codes counted, want 1", n)
	}

	// The right code gives the way in, and a scan of the picture proves it.
	rec = enter(t, f, path, code)
	body := rec.Body.String()
	imgs := qrtest.PageImages(body)
	if rec.Code != 200 || len(imgs) != 1 {
		t.Fatalf("the right code: %d, %d pictures\n%.300s", rec.Code, len(imgs), body)
	}
	if got := qrtest.ScanDataURL(t, imgs[0]); !strings.HasPrefix(got, "https://enterprise.google.com/android/enroll?et=") {
		t.Fatalf("the picture scans to %q", got)
	}
	if tokensIssued(f) != issued+1 {
		t.Fatalf("%d tokens issued, want 1", tokensIssued(f)-issued)
	}
	if n := adminCount(t, `SELECT count(*) FROM android_enrollment_tokens t JOIN join_links j ON j.id = t.join_id
		WHERE t.source = 'join' AND t.label = 'Kemi''s phone' AND j.uses = 1`); n != 1 {
		t.Fatal("the token is not recorded against its link, or the use was not counted")
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE action = 'android.join_used'`); n != 1 {
		t.Fatal("the use was not audited")
	}

	// A link for one device is spent. The right code no longer works.
	rec = enter(t, f, path, code)
	if rec.Code != http.StatusNotFound || tokensIssued(f) != issued+1 {
		t.Fatalf("a spent link was used again: %d", rec.Code)
	}

	// Neither secret is stored where it can be read back.
	secret := path[strings.LastIndex(path, "/")+1:]
	if n := adminCount(t, `SELECT count(*) FROM join_links WHERE code_hash = $1 OR code_hash NOT LIKE '$argon2id$%' OR name = $2`, code, secret); n != 0 {
		t.Fatal("the code is stored in the clear")
	}
}

func TestABulkLinkStopsAtItsLimitAndTheCodeStopsWithIt(t *testing.T) {
	f := selfReady(t)
	path, code := makeJoin(t, f, joinForm("Kano field team", "3", "168", "personal"))
	issued := tokensIssued(f)
	for i := 1; i <= 3; i++ {
		if rec := enter(t, f, path, code); rec.Code != 200 {
			t.Fatalf("device %d: %d", i, rec.Code)
		}
	}
	rec := enter(t, f, path, code)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("the fourth device: %d", rec.Code)
	}
	if got := tokensIssued(f) - issued; got != 3 {
		t.Fatalf("Google issued %d tokens for a link of 3", got)
	}
	// Each device is numbered, so the team's phones can be told apart.
	for _, want := range []string{"Kano field team 1", "Kano field team 2", "Kano field team 3"} {
		if n := adminCount(t, `SELECT count(*) FROM android_enrollment_tokens WHERE label = $1`, want); n != 1 {
			t.Fatalf("no token labelled %q", want)
		}
	}
	// The page for the person who opens it late says it is over.
	if rec := open(t, f, "GET", hostA, path, nil, desktopUA); rec.Code != http.StatusNotFound {
		t.Fatalf("opening a full link: %d", rec.Code)
	}
}

func TestAmongAcrowdOnlyTheLimitGetsIn(t *testing.T) {
	f := selfReady(t)
	path, code := makeJoin(t, f, joinForm("Crowd", "5", "168", "personal"))
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 14; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Different addresses, as a real crowd is, so the per-address
			// limit is not what stops them.
			r := httptest.NewRequest("POST", "http://"+hostA+path, strings.NewReader(url.Values{"code": {code}}.Encode()))
			r.Host = hostA
			r.RemoteAddr = "198.51.100." + string(rune('1'+i%9)) + ":5000"
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			f.h.ServeHTTP(rec, r)
			if rec.Code == 200 {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if ok != 5 {
		t.Fatalf("%d of 14 people at once got in, want exactly 5", ok)
	}
	if n := adminCount(t, `SELECT uses FROM join_links WHERE name = 'Crowd'`); n != 5 {
		t.Fatalf("%d uses counted", n)
	}
}

func TestALinkEndsWhenItsTimeIsUp(t *testing.T) {
	f := selfReady(t)
	path, code := makeJoin(t, f, joinForm("Short", "10", "24", "personal"))
	issued := tokensIssued(f)
	exec(t, `UPDATE join_links SET expires_at = now() - interval '1 minute'`)
	if rec := enter(t, f, path, code); rec.Code != http.StatusNotFound {
		t.Fatalf("an expired link took the right code: %d", rec.Code)
	}
	if tokensIssued(f) != issued {
		t.Fatal("Google was asked for a token on an expired link")
	}
	if rec := open(t, f, "GET", hostA, path, nil, desktopUA); rec.Code != http.StatusNotFound {
		t.Fatalf("opening an expired link: %d", rec.Code)
	}
}

func TestTenWrongCodesPauseTheLink(t *testing.T) {
	f := selfReady(t)
	path, code := makeJoin(t, f, joinForm("Guessed at", "5", "168", "personal"))
	issued := tokensIssued(f)
	bad := wrongCode(code)
	for i := 0; i < 10; i++ {
		if rec := enter(t, f, path, bad); rec.Code != http.StatusUnauthorized {
			t.Fatalf("wrong code %d: %d", i+1, rec.Code)
		}
	}
	// Paused: even the right code is refused, and it says why.
	rec := enter(t, f, path, code)
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), "paused") {
		t.Fatalf("the right code during the pause: %d", rec.Code)
	}
	if tokensIssued(f) != issued {
		t.Fatal("a paused link gave a way in")
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE action = 'android.join_paused'`); n != 1 {
		t.Fatal("the pause was not audited")
	}
	// After the hour, the right code works again.
	exec(t, `UPDATE join_links SET locked_until = now() - interval '1 second'`)
	if rec := enter(t, f, path, code); rec.Code != 200 {
		t.Fatalf("after the pause: %d", rec.Code)
	}
}

func TestACancelledLinkIsDeadAtOnceAndOnlyAnAdministratorMakesOrCancelsOne(t *testing.T) {
	f := selfReady(t)
	for _, who := range []string{"a-employee", "a-helpdesk", "a-auditor", "a-secmgr"} {
		rec := postForm(t, f, who, "/android/join", joinForm("x", "1", "24", "personal"))
		if rec.Code != http.StatusSeeOther || !strings.Contains(said(rec), "may not do that") {
			t.Fatalf("%s made a link: %d %q", who, rec.Code, said(rec))
		}
	}
	if n := adminCount(t, `SELECT count(*) FROM join_links`); n != 0 {
		t.Fatal("a role that may not, made a link")
	}
	path, code := makeJoin(t, f, joinForm("Cancel me", "5", "168", "personal"))
	var id string
	queryString(t, `SELECT id::text FROM join_links WHERE name = 'Cancel me'`, &id)
	if rec := postForm(t, f, "a-helpdesk", "/android/join/"+id+"/cancel", url.Values{}); !strings.Contains(said(rec), "may not do that") {
		t.Fatalf("helpdesk cancelled a link: %q", said(rec))
	}
	if rec := postForm(t, f, "a-itadmin", "/android/join/"+id+"/cancel", url.Values{}); !strings.Contains(said(rec), "Cancelled") {
		t.Fatalf("cancel: %q", said(rec))
	}
	issued := tokensIssued(f)
	if rec := enter(t, f, path, code); rec.Code != http.StatusNotFound {
		t.Fatalf("a cancelled link took the right code: %d", rec.Code)
	}
	if tokensIssued(f) != issued {
		t.Fatal("a cancelled link gave a way in")
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE action = 'android.join_cancelled'`); n != 1 {
		t.Fatal("the cancellation was not audited")
	}
}

func TestAJoinLinkBelongsToItsOwnOrganisation(t *testing.T) {
	f := selfReady(t)
	path, code := makeJoin(t, f, joinForm("Kalesi only", "5", "168", "personal"))
	issued := tokensIssued(f)
	for _, method := range []string{"GET", "POST"} {
		var vals url.Values
		if method == "POST" {
			vals = url.Values{"code": {code}}
		}
		if rec := open(t, f, method, hostB, path, vals, desktopUA); rec.Code != http.StatusNotFound {
			t.Fatalf("%s at another organisation's address: %d", method, rec.Code)
		}
	}
	if tokensIssued(f) != issued {
		t.Fatal("a link opened at another organisation's address gave a way in")
	}
	// Not a join secret at all.
	if rec := open(t, f, "GET", hostA, "/join/not-a-real-secret", nil, desktopUA); rec.Code != http.StatusNotFound {
		t.Fatalf("a made-up link: %d", rec.Code)
	}
}

func TestACompanyLinkGivesTheWelcomeScreenCodeAndAFormFromAnotherSiteIsRefused(t *testing.T) {
	f := selfReady(t)
	path, code := makeJoin(t, f, joinForm("Company phones", "2", "168", "company"))
	rec := enter(t, f, path, code)
	imgs := qrtest.PageImages(rec.Body.String())
	if rec.Code != 200 || len(imgs) != 1 {
		t.Fatalf("company phone: %d, %d pictures", rec.Code, len(imgs))
	}
	got := qrtest.ScanDataURL(t, imgs[0])
	var payload map[string]any
	if json.Unmarshal([]byte(got), &payload) != nil || strings.Contains(got, "enterprise.google.com") {
		t.Fatalf("a company phone was not given Google's provisioning payload: %q", got)
	}
	if !strings.Contains(rec.Body.String(), "six times") {
		t.Fatal("the page does not say to tap six times")
	}
	// A form posted from another site is refused.
	issued := tokensIssued(f)
	r := httptest.NewRequest("POST", "http://"+hostA+path, strings.NewReader(url.Values{"code": {code}}.Encode()))
	r.Host = hostA
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://evil.example")
	out := httptest.NewRecorder()
	f.h.ServeHTTP(out, r)
	if out.Code != http.StatusForbidden || tokensIssued(f) != issued {
		t.Fatalf("a cross-site post: %d", out.Code)
	}
}

func TestTheAdministratorSeesTheCountButNeverTheCodeAgain(t *testing.T) {
	f := selfReady(t)
	path, code := makeJoin(t, f, joinForm("Watch me", "4", "48", "personal"))
	enter(t, f, path, code)
	page := f.asPerson(t, "GET", hostA, "/android", tenantA, "o.martins", "it_admin", "o.martins@kalesi.example", nil, desktopUA)
	body := page.Body.String()
	secret := path[strings.LastIndex(path, "/")+1:]
	if strings.Contains(body, secret) || joinCodeRE.MatchString(body) {
		t.Fatal("the page shows the link's secret or its code after it was made")
	}
	if !strings.Contains(body, "Watch me") || !strings.Contains(body, "1 of 4") {
		t.Fatalf("the page does not show the count:\n%.600s", body)
	}
}

func TestJoinLimitsAreChecked(t *testing.T) {
	f := selfReady(t)
	for name, vals := range map[string]url.Values{
		"no name":                 joinForm("  ", "1", "24", "personal"),
		"no devices":              joinForm("x", "0", "24", "personal"),
		"too many devices":        joinForm("x", "5001", "24", "personal"),
		"not a number":            joinForm("x", "lots", "24", "personal"),
		"a lifetime not on offer": joinForm("x", "1", "5", "personal"),
		"no lifetime":             joinForm("x", "1", "", "personal"),
	} {
		rec := postForm(t, f, "a-itadmin", "/android/join", vals)
		if rec.Code != http.StatusSeeOther || said(rec) == "" {
			t.Errorf("%s: %d %q", name, rec.Code, said(rec))
		}
	}
	if n := adminCount(t, `SELECT count(*) FROM join_links`); n != 0 {
		t.Fatalf("%d links were made from bad forms", n)
	}
}
