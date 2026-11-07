package directory

import (
	"errors"
	"testing"
)

// A customer cannot take a name the operator's own hostnames use.
func TestAReservedNameCannotBeACustomersShortName(t *testing.T) {
	for _, s := range []string{"app", "www", "admin", "  App  ", "LOGIN", "mdm"} {
		if _, err := cleanSlug(s); !errors.Is(err, ErrSlugTaken) {
			t.Errorf("%q was allowed as a short name (err %v)", s, err)
		}
	}
	for _, s := range []string{"kalesi", "app-store", "my-app", "kalesi2"} {
		if got, err := cleanSlug(s); err != nil || got != s {
			t.Errorf("%q should be allowed, got %q, %v", s, got, err)
		}
	}
	// The old rules still hold.
	for _, s := range []string{"", "-x", "x-", "a b", "a.b", "é"} {
		if _, err := cleanSlug(s); !errors.Is(err, ErrBadSlug) {
			t.Errorf("%q should be a bad name, err %v", s, err)
		}
	}
}
