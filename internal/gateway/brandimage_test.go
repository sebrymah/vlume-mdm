package gateway

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// T4: the logo and the favicon are the tenant's, on every page, on the
// tab, in the report's band, and served per hostname with no session.

func tinyPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{R: 20, G: 110, B: 100, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png: %v", err)
	}
	return buf.Bytes()
}

func uploadImage(t *testing.T, f fixture, bearer, kind string, file []byte) *httptest.ResponseRecorder {
	t.Helper()
	cookie := f.cookie(t, bearer)
	sess, err := f.sessions.Verify(cookie)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("csrf", f.g.csrfFor(sess.TenantID, sess.Subject, sess.Role))
	_ = mw.WriteField("return", "/branding")
	_ = mw.WriteField("kind", kind)
	fw, _ := mw.CreateFormFile("file", kind+".bin")
	_, _ = fw.Write(file)
	_ = mw.Close()
	r := httptest.NewRequest("POST", "http://"+hostA+"/branding/image", &body)
	r.Host = hostA
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	return rec
}

func TestTheLogoAndFaviconAreTheTenantsOnEveryPageAndNoneOfAnothers(t *testing.T) {
	f := newFixture(t)
	logo := tinyPNG(t, 40, 16)
	if rec := uploadImage(t, f, "a-itadmin", "logo", logo); !strings.Contains(said(rec), "Saved") {
		t.Fatalf("logo upload: %q", said(rec))
	}
	if rec := uploadImage(t, f, "a-itadmin", "favicon", tinyPNG(t, 16, 16)); !strings.Contains(said(rec), "Saved") {
		t.Fatalf("favicon upload: %q", said(rec))
	}
	// Served per hostname with no session; tenant B has none.
	rec := raw(t, f, req(t, "GET", hostA, "/brand/logo", ""))
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "image/png" || !bytes.Equal(rec.Body.Bytes(), logo) {
		t.Fatalf("logo: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	if rec := raw(t, f, req(t, "GET", hostB, "/brand/logo", "")); rec.Code != 404 {
		t.Fatalf("tenant B served tenant A's logo: %d", rec.Code)
	}
	if rec := raw(t, f, req(t, "GET", hostA, "/brand/favicon.ico", "")); rec.Code != 200 {
		t.Fatalf("favicon: %d", rec.Code)
	}
	// On the page: the favicon link and the logo in the header.
	_, page := getHTML(t, f, hostA, "/devices", "a-helpdesk")
	if !strings.Contains(page, `rel="icon" href="/brand/favicon.ico"`) || !strings.Contains(page, `src="/brand/logo"`) {
		t.Fatal("the page does not carry the favicon and the logo")
	}
	// In the report's band.
	pdf := raw(t, f, req(t, "GET", hostA, "/reports/compliance.pdf", "a-itadmin"))
	if !strings.Contains(pdf.Body.String(), "/Subtype /Image /Width 40 /Height 16") || !strings.Contains(pdf.Body.String(), "/Im1 Do") {
		t.Fatal("the PDF band does not carry the logo")
	}
	// Refusals: not an image, too big, the help desk.
	if rec := uploadImage(t, f, "a-itadmin", "logo", []byte("<html><script>alert(1)</script></html>")); !strings.Contains(said(rec), "not a PNG") {
		t.Fatalf("an HTML file was accepted as a logo: %q", said(rec))
	}
	if rec := uploadImage(t, f, "a-itadmin", "favicon", bytes.Repeat([]byte{0x89, 'P', 'N', 'G', 13, 10, 26, 10}, 9000)); !strings.Contains(said(rec), "KB") {
		t.Fatalf("an oversized favicon was accepted: %q", said(rec))
	}
	if rec := uploadImage(t, f, "a-helpdesk", "logo", logo); !strings.Contains(said(rec), "may not") {
		t.Fatalf("the help desk changed the logo: %q", said(rec))
	}
	// The logo still serves as it was.
	if rec := raw(t, f, req(t, "GET", hostA, "/brand/logo", "")); !bytes.Equal(rec.Body.Bytes(), logo) {
		t.Fatal("a refused upload changed the logo")
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'branding.logo.saved'`, tenantA); n != 1 {
		t.Fatal("the logo save was not audited")
	}
}
