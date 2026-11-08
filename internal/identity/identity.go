// Package identity turns a person at a tenant's own identity provider into a
// subject and a role this platform understands.
//
// Every tenant brings their own provider. Kalesi signs in against their
// Microsoft Entra tenant, Arbor against theirs, and neither has an account
// here. That is requirement R11 and it is also the only shape that survives
// an enterprise security review: we never hold a password, we never run a
// password reset, and when a tenant disables someone's account they are
// disabled here at their next sign-in without anyone telling us.
//
// What this package is NOT allowed to do: decide what anyone may then do.
// That is authz, and it stays the single matrix. All that happens here is the
// mapping from a group at the provider to a role in that matrix.
//
// Provider SDK imports live in this package and its oidc.go file only. That
// is the portability rule from the specification, and it is the reason the
// gateway talks to an interface it defines itself.
package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/jackc/pgx/v5"

	"platform/internal/authz"
)

var (
	// ErrNotConfigured is a tenant that has not finished the setup wizard.
	// It is separated from a failure because it is not one: it is a tenant
	// who has more to do, and the console says so rather than showing an
	// error page.
	ErrNotConfigured = errors.New("identity: this tenant has no identity provider configured")

	ErrNoRole  = errors.New("identity: no group on this account maps to a role")
	ErrNoToken = errors.New("identity: the provider returned no identity token")
	ErrNonce   = errors.New("identity: the identity token does not answer this sign-in request")
)

// Config is one tenant's provider, already unsealed. It is built by the
// caller from what the directory holds, so this package never touches the
// database row or the sealing key.
type Config struct {
	TenantID     uuid.UUID
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	// RoleClaim names the claim carrying the person's groups. Microsoft
	// Entra ID emits "groups" once group claims are switched on for the
	// application registration. Google Workspace does not emit groups at all
	// without a directory sync, so a Google tenant usually maps a custom
	// claim instead. Making this configurable is cheaper than guessing.
	RoleClaim string

	// Protocol is "oidc" (the default when empty) or "saml". Under SAML the
	// fields above keep their meaning with one shift each: Issuer is the
	// provider's entity id, ClientID is OUR entity id (the audience), and
	// RedirectURL is our assertion consumer service. There is no client
	// secret; trust runs through SAMLCertificate, the provider's signing
	// certificate in PEM.
	Protocol        string
	SAMLSSOURL      string
	SAMLCertificate string
	// Single logout (0043): the provider's logout URL, and our own
	// signing key and certificate, PEM, made on first need and sealed
	// under the tenant's key in the row. Empty means no single logout.
	SAMLSLOURL      string
	SAMLSigningKey  string
	SAMLSigningCert string
	// LocalMFA is who must have a second factor when the tenant keeps its
	// own accounts: "admins" or "everyone" (0044).
	LocalMFA string
}

// Claims is what we keep from an identity token. Deliberately small: a wider
// struct invites someone to start making decisions from provider-specific
// fields, and then the provider is no longer swappable.
type Claims struct {
	Subject string
	Email   string
	Name    string
	Groups  []string
}

// RoleMap is a tenant's group-to-role mapping, keyed by the exact claim value.
type RoleMap map[string]authz.Role

// Querier is the slice of a transaction this package needs. Taking an
// interface rather than *data.Tx keeps the dependency pointing one way and
// lets the mapping be tested without a database.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// LoadRoleMap reads the mapping inside the caller's tenant transaction, so
// row-level security scopes it. There is no tenant argument for the same
// reason there is none anywhere else in the data layer.
func LoadRoleMap(ctx context.Context, tx Querier) (RoleMap, error) {
	rows, err := tx.Query(ctx, `SELECT claim_value, role FROM tenant_role_map`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := RoleMap{}
	for rows.Next() {
		var value, role string
		if err := rows.Scan(&value, &role); err != nil {
			return nil, err
		}
		r, err := authz.Parse(role)
		if err != nil {
			// A stored mapping naming a role that no longer exists. Skip it
			// rather than failing every sign-in for the tenant: the effect
			// is that people holding only that group cannot sign in, which
			// is the safe direction.
			continue
		}
		if !authz.FromTenantIdentity(r) {
			continue
		}
		out[value] = r
	}
	return out, rows.Err()
}

// MapRole picks the role for a person from the groups their provider sent.
//
// Two rules, both deliberate. A person in several mapped groups gets the
// highest-ranked of them, because the alternative is an answer that depends
// on map iteration order. A person whose groups match nothing gets no role
// and cannot sign in, because the alternative is a default, and a default
// here is a silent grant to everyone with an account at the tenant.
func MapRole(groups []string, m RoleMap) (authz.Role, error) {
	best := authz.Role("")
	for _, g := range groups {
		r, ok := m[g]
		if !ok {
			continue
		}
		if !authz.FromTenantIdentity(r) {
			continue
		}
		if best == "" || authz.Rank(r) > authz.Rank(best) {
			best = r
		}
	}
	if best == "" {
		return "", ErrNoRole
	}
	return best, nil
}

// groupsFrom pulls the role claim out of a decoded identity token.
//
// Providers disagree about the shape. Entra sends an array of strings, some
// send a single string, and a few send an array that has had numbers in it
// since a schema change nobody told us about. Take what can be read as a
// string, ignore the rest.
func groupsFrom(all map[string]any, claim string) []string {
	v, ok := all[claim]
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case string:
		return []string{t}
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// emailFrom picks the person's address from an identity token.
//
// An address the provider itself marks unverified (email_verified false) is
// not an address to hang a person on: it is whatever the person typed into
// their own profile. It is skipped, and the fallbacks the provider controls
// (preferred_username, upn) are used instead. Platform features that turn an
// address into a person (their own devices, a code for their own phone) are
// only as honest as this function. A provider that sends no email_verified at
// all is believed, because most do not send it and the alternative is that
// nobody could sign in; see the README on what that leaves open.
func emailFrom(all map[string]any) string {
	keys := []string{"email", "preferred_username", "upn"}
	switch v := all["email_verified"].(type) {
	case bool:
		if !v {
			keys = keys[1:]
		}
	case string:
		if strings.EqualFold(v, "false") {
			keys = keys[1:]
		}
	}
	return stringFrom(all, keys...)
}

func stringFrom(all map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := all[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func (c Config) validate() error {
	switch c.Protocol {
	case "", ProtocolOIDC:
		if c.Issuer == "" || c.ClientID == "" || c.RedirectURL == "" {
			return fmt.Errorf("%w: issuer, client id and redirect url are all required", ErrNotConfigured)
		}
	case ProtocolSAML:
		if c.Issuer == "" || c.ClientID == "" || c.RedirectURL == "" ||
			c.SAMLSSOURL == "" || c.SAMLCertificate == "" {
			return fmt.Errorf("%w: entity id, sign-in url and certificate are all required", ErrNotConfigured)
		}
	case ProtocolLocal:
		// No provider to talk to: a local tenant's sign-in is the
		// gateway's own form, and neither adapter has anything to do.
		return ErrWrongProtocol
	default:
		return fmt.Errorf("%w: unknown protocol %q", ErrNotConfigured, c.Protocol)
	}
	return nil
}

// IsSAML says which adapter a tenant's sign-in goes through.
func (c Config) IsSAML() bool { return c.Protocol == ProtocolSAML }

// IsLocal says the tenant has no identity provider: its people are
// accounts held here (0044).
func (c Config) IsLocal() bool { return c.Protocol == ProtocolLocal }

// IsOIDC is the default: an empty protocol is OIDC.
func (c Config) IsOIDC() bool { return c.Protocol == "" || c.Protocol == ProtocolOIDC }
