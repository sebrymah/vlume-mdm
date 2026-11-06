package identity

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"platform/internal/identity/idptest"
)

// These run against a real OpenID Connect provider: real discovery, a real
// JWKS, a real RSA signature and a real PKCE exchange, over real HTTP. The
// point is that the checks below are the ones a Microsoft Entra sign-in goes
// through, not a fake's approximation of them.

const clientID = "kalesi-console"

func provider(t *testing.T) (*idptest.Server, Config, *OIDC) {
	t.Helper()
	s, err := idptest.New(clientID)
	if err != nil {
		t.Fatalf("idptest: %v", err)
	}
	t.Cleanup(s.Close)
	cfg := Config{
		Issuer:       s.Issuer(),
		ClientID:     clientID,
		ClientSecret: "the-client-secret",
		RedirectURL:  "https://mdm.kalesi.example/signin/callback",
		RoleClaim:    "groups",
	}
	return s, cfg, NewOIDC()
}

// authorize walks the redirect the browser would follow and comes back with
// the code the provider handed out.
func authorize(t *testing.T, authURL string) (code, state string) {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: got %d, want a redirect back", resp.StatusCode)
	}
	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	return u.Query().Get("code"), u.Query().Get("state")
}

func signIn(t *testing.T, s *idptest.Server, cfg Config, o *OIDC, p idptest.Person) (Claims, error) {
	t.Helper()
	ctx := context.Background()
	s.SignInAs(p)

	verifier := NewVerifier()
	authURL, err := o.AuthURL(ctx, cfg, "state-1", "nonce-1", verifier)
	if err != nil {
		t.Fatalf("auth url: %v", err)
	}
	code, state := authorize(t, authURL)
	if state != "state-1" {
		t.Fatalf("the provider returned state %q", state)
	}
	return o.Exchange(ctx, cfg, code, verifier, "nonce-1")
}

var martins = idptest.Person{
	Subject: "9f2c1a40-0000-4000-8000-000000000001",
	Email:   "o.martins@kalesi.example",
	Name:    "O. Martins",
	Groups:  []string{"All-Staff", "IT-Operations"},
}

func TestASignInCompletesAndCarriesTheClaims(t *testing.T) {
	s, cfg, o := provider(t)
	claims, err := signIn(t, s, cfg, o, martins)
	if err != nil {
		t.Fatalf("sign-in: %v", err)
	}
	if claims.Subject != martins.Subject {
		t.Fatalf("subject: got %q", claims.Subject)
	}
	if claims.Email != martins.Email || claims.Name != martins.Name {
		t.Fatalf("got %+v", claims)
	}
	if len(claims.Groups) != 2 {
		t.Fatalf("groups: got %v", claims.Groups)
	}
}

// PKCE asserted rather than assumed. The fake provider refuses an
// authorization request without a challenge, so dropping it would fail
// everything above; this checks the other half, that the verifier is sent
// at the token endpoint.
func TestPKCEIsActuallySent(t *testing.T) {
	s, cfg, o := provider(t)
	if _, err := signIn(t, s, cfg, o, martins); err != nil {
		t.Fatalf("sign-in: %v", err)
	}
	if v := s.LastTokenForm.Get("code_verifier"); v == "" {
		t.Fatal("no code_verifier reached the token endpoint")
	}
	if m := s.LastTokenForm.Get("grant_type"); m != "authorization_code" {
		t.Fatalf("grant_type: got %q", m)
	}
}

// The check people leave out. Without it, an identity token minted for any
// other application registered at the same provider signs someone in here,
// and at a large customer that is dozens of applications, some of which let
// anyone self-register.
func TestATokenForAnotherApplicationIsRefused(t *testing.T) {
	s, cfg, o := provider(t)
	s.WrongAudience = "some-other-app-at-the-same-provider"
	if _, err := signIn(t, s, cfg, o, martins); err == nil {
		t.Fatal("an identity token for another application signed someone in")
	}
}

func TestATokenSignedWithAnUnpublishedKeyIsRefused(t *testing.T) {
	s, cfg, o := provider(t)
	s.WrongKey = true
	if _, err := signIn(t, s, cfg, o, martins); err == nil {
		t.Fatal("a token signed with a key the provider does not publish was accepted")
	}
}

// The nonce ties the token to the sign-in this browser started. Without it a
// token captured from one sign-in replays into another.
func TestATokenAnsweringAnotherSignInIsRefused(t *testing.T) {
	s, cfg, o := provider(t)
	s.StaleNonce = true
	_, err := signIn(t, s, cfg, o, martins)
	if err == nil {
		t.Fatal("a token minted for a different sign-in was accepted")
	}
	if !strings.Contains(err.Error(), "sign-in request") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

func TestTheWrongCodeVerifierIsRefused(t *testing.T) {
	s, cfg, o := provider(t)
	ctx := context.Background()
	s.SignInAs(martins)

	authURL, err := o.AuthURL(ctx, cfg, "state-1", "nonce-1", NewVerifier())
	if err != nil {
		t.Fatalf("auth url: %v", err)
	}
	code, _ := authorize(t, authURL)

	// A different verifier: what an attacker holding only the code has.
	if _, err := o.Exchange(ctx, cfg, code, NewVerifier(), "nonce-1"); err == nil {
		t.Fatal("a code was exchanged without the verifier that started it")
	}
}

func TestACodeIsGoodOnce(t *testing.T) {
	s, cfg, o := provider(t)
	ctx := context.Background()
	s.SignInAs(martins)

	verifier := NewVerifier()
	authURL, err := o.AuthURL(ctx, cfg, "state-1", "nonce-1", verifier)
	if err != nil {
		t.Fatalf("auth url: %v", err)
	}
	code, _ := authorize(t, authURL)

	if _, err := o.Exchange(ctx, cfg, code, verifier, "nonce-1"); err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	if _, err := o.Exchange(ctx, cfg, code, verifier, "nonce-1"); err == nil {
		t.Fatal("the same code was exchanged twice")
	}
}

// A tenant pointing us at a server that then claims to be Microsoft. The
// discovery document's own issuer has to match the one we asked for.
func TestAProviderThatLiesAboutItsIssuerIsRefused(t *testing.T) {
	s, cfg, o := provider(t)
	cfg.Issuer = strings.Replace(s.Issuer(), "127.0.0.1", "localhost", 1)
	if _, err := o.AuthURL(context.Background(), cfg, "s", "n", NewVerifier()); err == nil {
		t.Fatal("a provider whose document names another issuer was accepted")
	}
}

func TestAProviderThatIsNotThereIsReportedNotGuessed(t *testing.T) {
	_, cfg, o := provider(t)
	cfg.Issuer = "http://127.0.0.1:1/nothing-here"
	_, err := o.AuthURL(context.Background(), cfg, "s", "n", NewVerifier())
	if err == nil {
		t.Fatal("an unreachable provider produced a sign-in URL")
	}
	if !strings.Contains(err.Error(), "configuration") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

// Discovery is one HTTP round trip per issuer per hour, not one per sign-in.
func TestDiscoveryIsCachedPerIssuer(t *testing.T) {
	s, cfg, o := provider(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := o.AuthURL(ctx, cfg, "s", "n", NewVerifier()); err != nil {
			t.Fatalf("auth url %d: %v", i, err)
		}
	}
	o.mu.Lock()
	n := len(o.cache)
	o.mu.Unlock()
	if n != 1 {
		t.Fatalf("cached %d providers for one issuer", n)
	}
	_ = s
}

// The sign-in URL has to carry everything the provider needs, and the
// challenge method has to be S256. "plain" is still in the specification and
// is worth nothing.
func TestTheSignInURLCarriesTheRightParameters(t *testing.T) {
	_, cfg, o := provider(t)
	raw, err := o.AuthURL(context.Background(), cfg, "state-1", "nonce-1", NewVerifier())
	if err != nil {
		t.Fatalf("auth url: %v", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := u.Query()
	for k, want := range map[string]string{
		"client_id":             clientID,
		"response_type":         "code",
		"state":                 "state-1",
		"nonce":                 "nonce-1",
		"code_challenge_method": "S256",
		"redirect_uri":          cfg.RedirectURL,
	} {
		if q.Get(k) != want {
			t.Fatalf("%s: got %q, want %q", k, q.Get(k), want)
		}
	}
	if q.Get("code_challenge") == "" {
		t.Fatal("no code_challenge")
	}
	// Nothing beyond who the person is.
	if scope := q.Get("scope"); !strings.Contains(scope, "openid") ||
		strings.Contains(scope, "Mail") || strings.Contains(scope, "Files") {
		t.Fatalf("scope: got %q", scope)
	}
}

func TestAPersonWithNoMappedGroupCompletesSignInButGetsNoRole(t *testing.T) {
	s, cfg, o := provider(t)
	claims, err := signIn(t, s, cfg, o, idptest.Person{
		Subject: "9f2c1a40-0000-4000-8000-000000000002",
		Email:   "t.eze@kalesi.example",
		Groups:  []string{"Canteen"},
	})
	// The sign-in itself is fine: the provider says who they are, and it is
	// telling the truth. The refusal belongs one layer up, at the mapping,
	// and the two must not be conflated or the error message is wrong.
	if err != nil {
		t.Fatalf("sign-in: %v", err)
	}
	if _, err := MapRole(claims.Groups, kalesi); err == nil {
		t.Fatal("an unmapped group produced a role")
	}
}
