package identity

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDC is the adapter. One instance serves every tenant; the per-tenant
// settings arrive as a Config on each call, so nothing about a tenant is held
// in a field where it could be read by the next request.
//
// Microsoft Entra ID and Google Workspace are both plain OpenID Connect
// providers, so they are the same adapter with different issuers. Okta, Ping
// and Keycloak are too. A provider that is not OIDC, which in practice means
// an old SAML deployment, needs a second adapter behind the same interface
// and is listed as not built.
//
// Verified 2026-11-04: Microsoft identity platform OIDC metadata is published
// at https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration
// and Google's at https://accounts.google.com/.well-known/openid-configuration.
// Group claims in Entra are off by default and are switched on per
// application registration; Google Workspace does not emit group membership
// in the identity token at all. That is why RoleClaim is configurable and why
// the setup wizard has to ask.
type OIDC struct {
	mu    sync.Mutex
	cache map[string]cached
	// client bounds how long a provider's metadata endpoint can hold a
	// sign-in open. Without it a slow provider holds a request for as long
	// as it likes.
	client *http.Client
	ttl    time.Duration
	now    func() time.Time
}

type cached struct {
	p  *oidc.Provider
	at time.Time
}

func NewOIDC() *OIDC {
	return &OIDC{
		cache:  map[string]cached{},
		client: &http.Client{Timeout: 10 * time.Second},
		// Discovery documents change rarely, and signing keys rotate behind
		// the JWKS endpoint which go-oidc refetches on its own. An hour is
		// long enough to save the round trip and short enough that an issuer
		// changing its endpoints is picked up the same morning.
		ttl: time.Hour,
		now: time.Now,
	}
}

func (o *OIDC) discover(ctx context.Context, issuer string) (*oidc.Provider, error) {
	o.mu.Lock()
	hit, ok := o.cache[issuer]
	o.mu.Unlock()
	if ok && o.now().Sub(hit.at) < o.ttl {
		return hit.p, nil
	}

	// go-oidc checks that the document's own issuer matches the one asked
	// for, which is the check that stops a tenant pointing us at a server
	// that then claims to be Microsoft.
	p, err := oidc.NewProvider(oidc.ClientContext(ctx, o.client), issuer)
	if err != nil {
		return nil, fmt.Errorf("identity: could not read the provider's configuration: %w", err)
	}

	o.mu.Lock()
	o.cache[issuer] = cached{p: p, at: o.now()}
	o.mu.Unlock()
	return p, nil
}

func (o *OIDC) oauth(p *oidc.Provider, cfg Config) oauth2.Config {
	return oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  cfg.RedirectURL,
		// Nothing beyond who the person is. A wider scope would be asking a
		// tenant's security team for access to mail or files to run a device
		// console, which is the kind of request that ends a procurement.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}
}

// AuthURL is where the browser goes to sign in.
//
// state ties the callback to this browser's request, nonce ties the identity
// token to it, and verifier is PKCE. All three are held in the signed flow
// cookie the gateway sets alongside this redirect, so none of them is state
// we have to store.
func (o *OIDC) AuthURL(ctx context.Context, cfg Config, state, nonce, verifier string) (string, error) {
	if err := cfg.validate(); err != nil {
		return "", err
	}
	if cfg.IsSAML() {
		return "", ErrWrongProtocol
	}
	p, err := o.discover(ctx, cfg.Issuer)
	if err != nil {
		return "", err
	}
	oc := o.oauth(p, cfg)
	return oc.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	), nil
}

// Exchange turns the code from the callback into a verified identity.
//
// Everything that makes this safe happens inside Verify: the signature is
// checked against the provider's published keys, the issuer must match, and
// the audience must be this tenant's client id. The audience check is the one
// people leave out, and leaving it out means an identity token minted for any
// other application at the same provider signs someone in here.
func (o *OIDC) Exchange(ctx context.Context, cfg Config, code, verifier, nonce string) (Claims, error) {
	if err := cfg.validate(); err != nil {
		return Claims{}, err
	}
	if cfg.IsSAML() {
		return Claims{}, ErrWrongProtocol
	}
	p, err := o.discover(ctx, cfg.Issuer)
	if err != nil {
		return Claims{}, err
	}
	oc := o.oauth(p, cfg)

	tok, err := oc.Exchange(oidc.ClientContext(ctx, o.client), code,
		oauth2.VerifierOption(verifier))
	if err != nil {
		return Claims{}, fmt.Errorf("identity: the provider refused the sign-in code: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return Claims{}, ErrNoToken
	}

	idToken, err := p.Verifier(&oidc.Config{ClientID: cfg.ClientID}).Verify(ctx, raw)
	if err != nil {
		return Claims{}, fmt.Errorf("identity: the identity token did not verify: %w", err)
	}
	// The nonce proves this token was minted for the sign-in this browser
	// started, rather than replayed from another one.
	if idToken.Nonce != nonce {
		return Claims{}, ErrNonce
	}

	var all map[string]any
	if err := idToken.Claims(&all); err != nil {
		return Claims{}, fmt.Errorf("identity: could not read the identity token: %w", err)
	}

	c := Claims{
		Subject: idToken.Subject,
		Email:   emailFrom(all),
		Name:    stringFrom(all, "name", "given_name"),
		Groups:  groupsFrom(all, cfg.RoleClaim),
	}
	if c.Subject == "" {
		return Claims{}, fmt.Errorf("identity: the identity token names no subject")
	}
	return c, nil
}

// NewVerifier makes a PKCE code verifier.
//
// It is here rather than in the gateway for the same reason the rest of this
// file is: the gateway does not import an OAuth library, so the one function
// that needs one lives on this side of the boundary.
func NewVerifier() string { return oauth2.GenerateVerifier() }

// EndSessionURL is where the browser goes to end the provider's session
// too (RP-initiated logout), or "" when the provider does not offer one.
// The provider is told where to send the person afterwards and which
// application is asking; a provider that insists on an id_token_hint as
// well will still end the session at its own page and stop there.
func (o *OIDC) EndSessionURL(ctx context.Context, cfg Config, postLogout string) (string, error) {
	if err := cfg.validate(); err != nil {
		return "", err
	}
	if cfg.IsSAML() {
		return "", ErrWrongProtocol
	}
	p, err := o.discover(ctx, cfg.Issuer)
	if err != nil {
		return "", err
	}
	var extra struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if err := p.Claims(&extra); err != nil || extra.EndSession == "" {
		return "", nil
	}
	u, err := url.Parse(extra.EndSession)
	if err != nil || u.Scheme != "https" && !loopback(u.Host) {
		return "", nil
	}
	q := u.Query()
	q.Set("post_logout_redirect_uri", postLogout)
	q.Set("client_id", cfg.ClientID)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func loopback(host string) bool {
	h := host
	if i := strings.LastIndex(h, ":"); i > 0 {
		h = h[:i]
	}
	return h == "localhost" || h == "127.0.0.1" || h == "[::1]"
}
