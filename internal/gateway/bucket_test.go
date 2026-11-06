package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// T10: the export sent to a bucket the tenant names.

// fakeBucket is an S3-compatible store: it keeps what was put and the
// Authorization header it came with.
type fakeBucket struct {
	mu     sync.Mutex
	path   string
	body   []byte
	auth   string
	sha    string
	status int
}

func (b *fakeBucket) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<20))
		b.mu.Lock()
		b.path, b.body, b.auth = r.URL.Path, body, r.Header.Get("Authorization")
		b.sha = r.Header.Get("x-amz-content-sha256")
		status := b.status
		b.mu.Unlock()
		if status == 0 {
			status = 200
		}
		w.WriteHeader(status)
	})
}

func TestTheExportIsSentToTheTenantsOwnBucket(t *testing.T) {
	f := newFixture(t)
	b := &fakeBucket{}
	srv := httptest.NewServer(b.handler())
	defer srv.Close()

	vals := url.Values{
		"endpoint": {srv.URL}, "bucket": {"our-backups"}, "prefix": {"mdm"},
		"region": {"eu-west-1"}, "access_key": {"AKIAEXAMPLE"}, "secret_key": {"s3cret-key-value"},
	}
	rec := postForm(t, f, "a-super", "/export/bucket", vals)
	said := said(rec)
	if !strings.Contains(said, "Sent:") || !strings.Contains(said, "our-backups/mdm/kalesi-export-") {
		t.Fatalf("send: %q", said)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !strings.HasPrefix(b.path, "/our-backups/mdm/kalesi-export-") || !strings.HasSuffix(b.path, ".zip") {
		t.Fatalf("object path: %q", b.path)
	}
	if len(b.body) < 100 || string(b.body[:2]) != "PK" {
		t.Fatalf("the bucket did not get a zip: %d bytes", len(b.body))
	}
	// Signed, version 4, with the payload hashed into the signature and
	// the key id in the credential. The secret is nowhere in the request.
	if !strings.HasPrefix(b.auth, "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/") ||
		!strings.Contains(b.auth, "/eu-west-1/s3/aws4_request") ||
		!strings.Contains(b.auth, "SignedHeaders=host;x-amz-content-sha256;x-amz-date") {
		t.Fatalf("authorization: %q", b.auth)
	}
	if len(b.sha) != 64 {
		t.Fatalf("payload hash: %q", b.sha)
	}
	for _, secret := range []string{"s3cret-key-value", "AWS4s3cret"} {
		if strings.Contains(b.auth, secret) {
			t.Fatal("the secret key is in the request")
		}
	}
	// Audited by where it went, not by what opened it.
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'export.sent' AND object_ref LIKE '%our-backups/mdm/%'`, tenantA); n != 1 {
		t.Fatalf("%d export.sent audit rows", n)
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND object_ref LIKE '%s3cret%'`, tenantA); n != 0 {
		t.Fatal("the secret key reached the audit log")
	}
}

// The guard, which the fixture above has switched off so its bucket can
// be on loopback: a deployment refuses an endpoint whose name resolves to
// an address inside this platform's own network, and refuses it at dial
// time rather than at save time, so a name that resolves to one public
// and one private address is refused whole. The control --break-bucketssrf
// dials whatever the name resolves to.
func TestAnEndpointInsideThePlatformsOwnNetworkIsRefused(t *testing.T) {
	f := newFixture(t)
	b := &fakeBucket{}
	srv := httptest.NewServer(b.handler())
	defer srv.Close()

	// The same gateway with the test allowance off, which is how it runs
	// in a deployment.
	g := New(Config{
		Directory: f.g.dir, Store: f.g.store, Signer: f.g.signer, Identity: f.g.idp,
		Pipeline: f.pipe, CSRFKey: testKey, Sessions: f.sessions,
		Sealer: f.sealer, Enrol: f.enrol, InsecureCookies: true,
	})
	cookie := f.cookie(t, "a-super")
	sess, err := f.sessions.Verify(cookie)
	if err != nil {
		t.Fatal(err)
	}
	// https, as a deployment insists, pointing at the loopback listener
	// above: the refusal has to come from the guard, not from the scheme.
	endpoint := strings.Replace(srv.URL, "http://", "https://", 1)
	vals := url.Values{
		"endpoint": {endpoint}, "bucket": {"our-backups"},
		"access_key": {"AKIAEXAMPLE"}, "secret_key": {"s3cret-key-value"},
		"csrf": {g.csrfFor(sess.TenantID, sess.Subject, sess.Role)},
	}
	r := httptest.NewRequest("POST", "http://"+hostA+"/export/bucket", strings.NewReader(vals.Encode()))
	r.Host = hostA
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	rec := httptest.NewRecorder()
	g.Handler().ServeHTTP(rec, r)

	if !strings.Contains(said(rec), "inside this platform's own network") {
		t.Fatalf("a loopback endpoint was not refused: %q", said(rec))
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.body) != 0 {
		t.Fatalf("%d bytes reached an endpoint inside the network", len(b.body))
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'export.sent'`, tenantA); n != 0 {
		t.Fatal("a refused send was recorded")
	}
}

func TestABucketThatRefusesIsSaidPlainlyAndNothingIsRecorded(t *testing.T) {
	f := newFixture(t)
	b := &fakeBucket{status: 403}
	srv := httptest.NewServer(b.handler())
	defer srv.Close()
	rec := postForm(t, f, "a-super", "/export/bucket", url.Values{
		"endpoint": {srv.URL}, "bucket": {"our-backups"},
		"access_key": {"AKIAEXAMPLE"}, "secret_key": {"wrong"},
	})
	if !strings.Contains(said(rec), "refused the upload") || !strings.Contains(said(rec), "Nothing was recorded") {
		t.Fatalf("refusal: %q", said(rec))
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'export.sent'`, tenantA); n != 0 {
		t.Fatal("a refused upload was recorded as sent")
	}
}

func TestAnIncompleteOrUnsafeBucketIsRefusedBeforeTheExportIsMade(t *testing.T) {
	f := newFixture(t)
	full := func(over map[string]string) url.Values {
		v := url.Values{"endpoint": {"https://s3.example"}, "bucket": {"b"},
			"access_key": {"AKIA"}, "secret_key": {"s"}}
		for k, val := range over {
			if val == "" {
				v.Del(k)
			} else {
				v.Set(k, val)
			}
		}
		return v
	}
	for _, c := range []struct{ field, value, want string }{
		{"endpoint", "", "not a web address"},
		{"endpoint", "ftp://s3.example", "https://"},
		{"endpoint", "https://user:pass@s3.example", "no username or password"},
		{"bucket", "", "bucket name"},
		{"bucket", "a/b", "no slashes"},
		{"access_key", "", "access key id"},
		{"secret_key", "", "secret access key"},
	} {
		rec := postForm(t, f, "a-super", "/export/bucket", full(map[string]string{c.field: c.value}))
		if !strings.Contains(said(rec), c.want) {
			t.Fatalf("%s=%q: %q", c.field, c.value, said(rec))
		}
	}
	// Only the role that may read everything may send everything.
	for _, who := range []string{"a-itadmin", "a-helpdesk", "a-auditor", "a-employee"} {
		rec := postForm(t, f, who, "/export/bucket", full(nil))
		if !strings.Contains(said(rec), "may not") && rec.Code != http.StatusForbidden {
			t.Fatalf("%s sent the export: %q (%d)", who, said(rec), rec.Code)
		}
	}
}
