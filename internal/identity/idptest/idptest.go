// Package idptest is a working OpenID Connect provider for tests.
//
// It exists because the alternative is a fake adapter, and a fake adapter
// tests nothing: it skips the signature check, the audience check, the nonce
// and the PKCE exchange, which are the four things that make the real one
// safe. This server does all of them for real, over real HTTP, with a real
// RSA key. The tests that use it exercise the same code path a Microsoft
// Entra sign-in does.
//
// It is a separate package rather than a _test.go file so the gateway tests
// and the identity tests can both reach it.
package idptest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Person is who the server signs in on the next authorization request.
type Person struct {
	Subject string
	Email   string
	Name    string
	Groups  []string
}

type grant struct {
	person    Person
	nonce     string
	challenge string
	clientID  string
}

type Server struct {
	http     *httptest.Server
	issuer   string
	mux      *http.ServeMux
	key      *rsa.PrivateKey
	ClientID string

	// Interactive turns the authorization endpoint into a page that asks
	// who is signing in, instead of signing in whoever was set last. Tests
	// leave it off. The local demo turns it on, because being able to pick
	// a role and watch the console change is the clearest way to show what
	// the role matrix actually does.
	Interactive bool
	// People are the accounts the picker offers.
	People []Person

	mu     sync.Mutex
	person Person
	codes  map[string]grant

	// Knobs for the tests that have to prove a check is doing work. Each one
	// breaks exactly one property of the identity token.

	// WrongAudience mints the token for another application at the same
	// provider. A verifier that does not check the audience accepts it.
	WrongAudience string
	// WrongKey signs with a key the published JWKS does not contain.
	WrongKey bool
	// StaleNonce puts a different nonce in the token than the one asked for.
	StaleNonce bool

	// LastTokenForm is what the token endpoint last received, so a test can
	// assert that PKCE was actually sent rather than assuming it.
	LastTokenForm url.Values
	// Logouts counts RP-initiated logouts; LastLogout is what the last one
	// carried.
	Logouts    int
	LastLogout url.Values
}

func New(clientID string) (*Server, error) {
	s, err := NewHandler(clientID, "")
	if err != nil {
		return nil, err
	}
	s.http = httptest.NewServer(s.mux)
	s.issuer = s.http.URL
	return s, nil
}

// NewHandler is the same provider for a caller that runs its own listener,
// which is how the local demo puts it on a fixed port the browser can reach.
func NewHandler(clientID, issuer string) (*Server, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	s := &Server{key: key, ClientID: clientID, codes: map[string]grant{}, issuer: issuer}
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("/.well-known/openid-configuration", s.discovery)
	s.mux.HandleFunc("/jwks", s.jwks)
	s.mux.HandleFunc("/authorize", s.authorize)
	s.mux.HandleFunc("/token", s.token)
	s.mux.HandleFunc("/logout", s.logout)
	return s, nil
}

// logout is the provider's end-session page: it forgets the person and
// sends them where the application asked, as a real provider does.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.Logouts++
	s.LastLogout = r.URL.Query()
	s.person = Person{}
	back := r.URL.Query().Get("post_logout_redirect_uri")
	s.mu.Unlock()
	if back != "" {
		http.Redirect(w, r, back, http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte("<!doctype html><title>Signed out</title><p>You are signed out.</p>"))
}

// LoggedOut says how many times the end-session page was used.
func (s *Server) LoggedOut() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Logouts
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) Close() {
	if s.http != nil {
		s.http.Close()
	}
}

func (s *Server) Issuer() string { return s.issuer }

// SignInAs sets who the next authorization request signs in.
func (s *Server) SignInAs(p Person) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.person = p
}

func (s *Server) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                s.issuer,
		"authorization_endpoint":                s.issuer + "/authorize",
		"token_endpoint":                        s.issuer + "/token",
		"jwks_uri":                              s.issuer + "/jwks",
		"end_session_endpoint":                  s.issuer + "/logout",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (s *Server) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := s.key.Public().(*rsa.PublicKey)
	writeJSON(w, map[string]any{"keys": []any{map[string]any{
		"kty": "RSA",
		"kid": "idptest",
		"use": "sig",
		"alg": "RS256",
		"n":   b64(pub.N.Bytes()),
		"e":   b64(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

// authorize is the sign-in page, with the signing-in already done. It records
// what the client asked for and bounces straight back with a code, so a test
// following redirects completes a whole sign-in without typing a password.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect := q.Get("redirect_uri")
	if redirect == "" {
		http.Error(w, "no redirect_uri", http.StatusBadRequest)
		return
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		// Refusing here is the point. If the adapter ever stops sending
		// PKCE, every test that signs in fails rather than quietly getting
		// weaker.
		http.Error(w, "this provider requires PKCE with S256", http.StatusBadRequest)
		return
	}

	// The picker, for the local demo. It posts back to this same endpoint
	// with the chosen account, so the rest of the flow is unchanged.
	if s.Interactive && r.Method == http.MethodGet && r.URL.Query().Get("who") == "" {
		s.picker(w, r)
		return
	}
	if who := q.Get("who"); who != "" {
		for _, p := range s.People {
			if p.Subject == who {
				s.SignInAs(p)
			}
		}
	}

	code := fmt.Sprintf("code-%d", time.Now().UnixNano())
	s.mu.Lock()
	s.codes[code] = grant{
		person:    s.person,
		nonce:     q.Get("nonce"),
		challenge: q.Get("code_challenge"),
		clientID:  q.Get("client_id"),
	}
	s.mu.Unlock()

	u, err := url.Parse(redirect)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	rq := u.Query()
	rq.Set("code", code)
	rq.Set("state", q.Get("state"))
	u.RawQuery = rq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.LastTokenForm = r.PostForm
	g, ok := s.codes[r.PostForm.Get("code")]
	delete(s.codes, r.PostForm.Get("code")) // a code is good once
	wrongAud, wrongKey, staleNonce := s.WrongAudience, s.WrongKey, s.StaleNonce
	s.mu.Unlock()

	if !ok {
		writeErr(w, "invalid_grant", "no such code")
		return
	}
	// PKCE, verified rather than assumed.
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if b64(sum[:]) != g.challenge {
		writeErr(w, "invalid_grant", "code_verifier does not match code_challenge")
		return
	}

	aud := g.clientID
	if wrongAud != "" {
		aud = wrongAud
	}
	nonce := g.nonce
	if staleNonce {
		nonce = "a-nonce-from-another-sign-in"
	}

	now := time.Now()
	claims := map[string]any{
		"iss":   s.issuer,
		"sub":   g.person.Subject,
		"aud":   aud,
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Unix(),
		"nonce": nonce,
		"email": g.person.Email,
		"name":  g.person.Name,
	}
	if g.person.Groups != nil {
		claims["groups"] = g.person.Groups
	}

	key := s.key
	if wrongKey {
		other, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			http.Error(w, "key", http.StatusInternalServerError)
			return
		}
		key = other
	}
	idToken, err := signJWT(key, claims)
	if err != nil {
		http.Error(w, "sign", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{
		"access_token": "access-" + g.person.Subject,
		"token_type":   "Bearer",
		"expires_in":   300,
		"id_token":     idToken,
	})
}

func signJWT(key *rsa.PrivateKey, claims map[string]any) (string, error) {
	head, err := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "idptest"})
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := b64(head) + "." + b64(body)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + b64(sig), nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}

// picker asks who is signing in. It exists only for the local demo and says
// so on the page, because a provider that signs anyone in without asking for
// anything is the opposite of what this platform requires in a deployment.
func (s *Server) picker(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in</title><style>
body{margin:0;font-family:Inter,system-ui,-apple-system,sans-serif;background:#F6F6F4;color:#1A1A18}
main{max-width:520px;margin:0 auto;padding:60px 24px}
h1{font-size:21px;font-weight:600;margin:0 0 6px}
p.sub{color:#5F5F58;font-size:13.5px;line-height:1.55;margin:0 0 26px}
.warn{background:#FFF4E0;border:1px solid #E8D5A8;border-radius:8px;padding:12px 14px;
      font-size:12.5px;color:#6B4E00;margin-bottom:24px;line-height:1.5}
a.who{display:flex;align-items:center;gap:12px;text-decoration:none;color:inherit;
      background:#fff;border:1px solid #E4E4E1;border-radius:9px;padding:13px 15px;margin-bottom:9px}
a.who:hover{border-color:#9b9b95}
.n{display:block;font-weight:600;font-size:14px}
.r{display:block;font-size:12px;color:#5F5F58;margin-top:2px}
.g{display:block;font-size:11px;color:#8a8a84;margin-top:3px;
   font-family:ui-monospace,Menlo,monospace}
</style></head><body><main>
<h1>Who is signing in?</h1>
<p class="sub">This stands in for your organisation&rsquo;s own identity provider.</p>
<div class="warn"><strong>Local demo only.</strong> There is no password here.
A real deployment signs in against the tenant&rsquo;s own Microsoft Entra or
Google Workspace directory, and this platform never holds a password.</div>`)

	q := r.URL.RawQuery
	for _, p := range s.People {
		fmt.Fprintf(w, `<a class="who" href="/authorize?%s&amp;who=%s">
<span><span class="n">%s</span><span class="r">%s</span><span class="g">%s</span></span></a>`,
			q, url.QueryEscape(p.Subject), p.Name, p.Email, strings.Join(p.Groups, ", "))
	}
	fmt.Fprint(w, `</main></body></html>`)
}
