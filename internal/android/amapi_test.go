package android

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A refusal from Google reaches an administrator's screen. It has to say
// what to do in words, not as the JSON envelope Google wraps it in.
func TestGoogleRefusalsReadAsASentence(t *testing.T) {
	body := `{ "error": { "code": 403, "message": "Android Management API has not been used in project 941214041204 before or it is disabled. Enable it by visiting https://console.developers.google.com/apis/api/androidmanagement.googleapis.com/overview?project=941214041204 then retry.", "status": "PERMISSION_DENIED", "details": [ { "@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "SERVICE_DISABLED", "domain": "googleapis.com" } ] } }`
	got := apiError{Status: 403, Body: body}.Error()
	for _, want := range []string{
		"Google refused (403 PERMISSION_DENIED, SERVICE_DISABLED)",
		"Enable it by visiting",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("the refusal does not say %q:\n%s", want, got)
		}
	}
	for _, junk := range []string{`"@type"`, `"details"`, `{ "error"`} {
		if strings.Contains(got, junk) {
			t.Fatalf("the refusal still shows Google's envelope (%s):\n%s", junk, got)
		}
	}

	// A refusal that drags a stack trace behind it loses the trace.
	traced := apiError{Status: 400, Body: `{"error":{"code":400,"message":"domain: \"androidenterprise.ApiErrors\" code: \"INSECURE_CALLBACK_URL\" debug_info: \"code: INSECURE_CALLBACK_URL\\nhttp status: 400\\ncause: com.google.Exception\\n\\tat com.google.Thing(Thing.java:36)\"","status":"INVALID_ARGUMENT"}}`}.Error()
	if !strings.Contains(traced, `code: "INSECURE_CALLBACK_URL"`) || strings.Contains(traced, "Thing.java") {
		t.Fatalf("the stack trace was not cut off: %s", traced)
	}

	// Not every bad answer is that envelope: a gateway's HTML page, say.
	// Those are shown as they came, so nothing is hidden.
	plain := apiError{Status: 502, Body: "<html>bad gateway</html>"}.Error()
	if !strings.Contains(plain, "Google answered 502: <html>bad gateway</html>") {
		t.Fatalf("a plain body was not passed through: %s", plain)
	}
}

// The credentials file carries the project, and the client has to know it:
// Google refuses to create a sign-up URL or an enterprise without it.
func TestTheClientNeedsTheProjectFromTheCredentials(t *testing.T) {
	key := `{"type":"service_account","client_email":"x@p.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n"}`
	if _, err := NewAMAPI(context.Background(), []byte(key)); err == nil {
		t.Fatal("a key with no project_id was accepted")
	}
	withProject := `{"type":"service_account","project_id":"mdm-test","client_email":"x@p.iam.gserviceaccount.com","private_key":"k"}`
	c, err := NewAMAPI(context.Background(), []byte(withProject))
	if err != nil {
		t.Fatalf("a complete key was refused: %v", err)
	}
	if c.project != "mdm-test" {
		t.Fatalf("project is %q", c.project)
	}
}

// The fake is as strict as Google about where it will send people back:
// https or nothing. A console that tests only against a lenient fake finds
// this out on its first real bind instead.
func TestTheFakeRefusesAPlainHTTPCallbackLikeGoogleDoes(t *testing.T) {
	f := NewFakeGoogle()
	defer f.Close()
	c := f.Client()
	if _, err := c.CreateSignupURL(context.Background(), "http://localhost:8090/android/callback"); err == nil ||
		!strings.Contains(err.Error(), "INSECURE_CALLBACK_URL") {
		t.Fatalf("an http callback was accepted: %v", err)
	}
	if _, err := c.CreateSignupURL(context.Background(), "https://localhost:8092/android/callback"); err != nil {
		t.Fatalf("an https callback was refused: %v", err)
	}
}

// The token's expiry is read from the field Google sends. The first real
// token taught this: an invitation that says it expires in the year 1 is
// an invitation nobody trusts.
func TestATokensExpiryIsReadFromGooglesField(t *testing.T) {
	f := NewFakeGoogle()
	defer f.Close()
	c := f.Client()
	ctx := context.Background()
	su, err := c.CreateSignupURL(ctx, "https://localhost:8092/android/callback")
	if err != nil {
		t.Fatal(err)
	}
	e, err := c.CreateEnterprise(ctx, su.Name, f.EnterpriseToken(su.Name), "Kalesi")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := c.CreateEnrollmentToken(ctx, e.Name, TokenInput{PolicyName: e.Name + "/policies/default", Lifetime: 7 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if tok.ExpiresAt.Year() < 2000 || tok.ExpiresAt.Before(time.Now()) {
		t.Fatalf("the expiry was not read from Google's answer: %v", tok.ExpiresAt)
	}
	if tok.ExpiresAt.After(time.Now().Add(2 * time.Hour)) {
		t.Fatalf("the expiry is not the one Google sent (an hour from now): %v", tok.ExpiresAt)
	}
}
