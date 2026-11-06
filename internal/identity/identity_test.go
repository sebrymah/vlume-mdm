package identity

import (
	"errors"
	"testing"

	"platform/internal/authz"
)

// The mapping Kalesi would set up in the wizard: their own Entra group names
// on the left, the roles in the matrix on the right.
var kalesi = RoleMap{
	"MDM-Owners":     authz.SuperAdmin,
	"IT-Operations":  authz.ITAdmin,
	"Security-Team":  authz.SecurityManager,
	"Service-Desk":   authz.Helpdesk,
	"Internal-Audit": authz.Auditor,
	"All-Staff":      authz.Employee,
}

func TestOneGroupMapsToItsRole(t *testing.T) {
	for group, want := range kalesi {
		got, err := MapRole([]string{group}, kalesi)
		if err != nil {
			t.Fatalf("%s: %v", group, err)
		}
		if got != want {
			t.Fatalf("%s: got %s, want %s", group, got, want)
		}
	}
}

// Nobody is in one group. The answer has to be the same every time, and the
// only ordering that is not arbitrary is the one by privilege.
func TestSeveralGroupsGiveTheHighestRole(t *testing.T) {
	cases := []struct {
		groups []string
		want   authz.Role
	}{
		{[]string{"All-Staff", "IT-Operations"}, authz.ITAdmin},
		{[]string{"IT-Operations", "All-Staff"}, authz.ITAdmin},
		{[]string{"Service-Desk", "Internal-Audit", "All-Staff"}, authz.Auditor},
		{[]string{"All-Staff", "MDM-Owners", "Service-Desk"}, authz.SuperAdmin},
		{[]string{"Security-Team", "IT-Operations"}, authz.SecurityManager},
	}
	for _, c := range cases {
		got, err := MapRole(c.groups, kalesi)
		if err != nil {
			t.Fatalf("%v: %v", c.groups, err)
		}
		if got != c.want {
			t.Fatalf("%v: got %s, want %s", c.groups, got, c.want)
		}
	}
	// Run the ambiguous case repeatedly: a map-order bug shows up as a test
	// that passes most of the time, which is worse than one that fails.
	for i := 0; i < 200; i++ {
		got, err := MapRole([]string{"All-Staff", "MDM-Owners", "Service-Desk"}, kalesi)
		if err != nil || got != authz.SuperAdmin {
			t.Fatalf("run %d gave %s (%v)", i, got, err)
		}
	}
}

// The single most important assertion in this package. A person who signs in
// successfully but matches no mapped group must get nothing. A default here
// would be a silent grant to every account at the tenant, including the ones
// an administrator has not thought about yet.
func TestNoMatchingGroupMeansNoRole(t *testing.T) {
	for name, groups := range map[string][]string{
		"no groups at all":   nil,
		"empty list":         {},
		"unmapped groups":    {"Canteen", "Lagos-Office", "Printer-Users"},
		"nearly right":       {"IT-Operation", "all-staff", "MDM_Owners"},
		"an empty string":    {""},
		"a role name itself": {"it_admin", "super_admin"},
	} {
		got, err := MapRole(groups, kalesi)
		if !errors.Is(err, ErrNoRole) {
			t.Fatalf("%s: got role %q and error %v, want no role", name, got, err)
		}
	}
}

// Group names are compared exactly. Entra treats display names as
// case-preserving, and quietly matching case would mean two different groups
// could map to one role without anyone choosing that.
func TestGroupNamesAreMatchedExactly(t *testing.T) {
	if _, err := MapRole([]string{"it-operations"}, kalesi); !errors.Is(err, ErrNoRole) {
		t.Fatal("a group name matched with different case")
	}
}

// The platform operator's role is not a tenant's to hand out. The database
// says so in a CHECK constraint; this is the other half, for a mapping that
// got in before the constraint existed or around it.
func TestATenantCannotMapAnyoneToThePlatformOperator(t *testing.T) {
	sneaky := RoleMap{"Admins": authz.Operator, "All-Staff": authz.Employee}
	got, err := MapRole([]string{"Admins"}, sneaky)
	if !errors.Is(err, ErrNoRole) {
		t.Fatalf("a tenant mapped a group to the platform operator: %s (%v)", got, err)
	}
	// And it does not poison the rest of the mapping.
	got, err = MapRole([]string{"Admins", "All-Staff"}, sneaky)
	if err != nil || got != authz.Employee {
		t.Fatalf("got %s (%v), want employee", got, err)
	}
}

func TestAnEmptyMappingLetsNobodyIn(t *testing.T) {
	if _, err := MapRole([]string{"IT-Operations"}, RoleMap{}); !errors.Is(err, ErrNoRole) {
		t.Fatal("an unconfigured tenant let someone in")
	}
}

// ------------------------------------------------------- reading the claim

func TestGroupsAreReadFromWhateverShapeTheProviderSends(t *testing.T) {
	cases := []struct {
		name  string
		token map[string]any
		claim string
		want  []string
	}{
		{"an array, which is what Entra sends",
			map[string]any{"groups": []any{"IT-Operations", "All-Staff"}}, "groups",
			[]string{"IT-Operations", "All-Staff"}},
		{"a single string",
			map[string]any{"groups": "IT-Operations"}, "groups",
			[]string{"IT-Operations"}},
		{"a custom claim name",
			map[string]any{"mdm_roles": []any{"Security-Team"}}, "mdm_roles",
			[]string{"Security-Team"}},
		{"an array with numbers in it",
			map[string]any{"groups": []any{"IT-Operations", float64(7), nil, "All-Staff"}}, "groups",
			[]string{"IT-Operations", "All-Staff"}},
		{"the claim is missing",
			map[string]any{"email": "o.martins@kalesi.example"}, "groups", nil},
		{"the claim is a number",
			map[string]any{"groups": float64(3)}, "groups", nil},
		{"the claim is an object",
			map[string]any{"groups": map[string]any{"a": 1}}, "groups", nil},
	}
	for _, c := range cases {
		got := groupsFrom(c.token, c.claim)
		if len(got) != len(c.want) {
			t.Fatalf("%s: got %v, want %v", c.name, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("%s: got %v, want %v", c.name, got, c.want)
			}
		}
	}
}

func TestTheNameAndEmailFallBackThroughTheUsualClaims(t *testing.T) {
	// Entra often sends preferred_username or upn rather than email.
	if got := stringFrom(map[string]any{"upn": "o.martins@kalesi.example"},
		"email", "preferred_username", "upn"); got != "o.martins@kalesi.example" {
		t.Fatalf("got %q", got)
	}
	if got := stringFrom(map[string]any{"email": ""}, "email", "upn"); got != "" {
		t.Fatalf("an empty claim was treated as a value: %q", got)
	}
}

func TestAnIncompleteConfigIsRefusedBeforeAnyNetworkCall(t *testing.T) {
	for name, c := range map[string]Config{
		"no issuer":   {ClientID: "c", RedirectURL: "https://x/cb"},
		"no client":   {Issuer: "https://i", RedirectURL: "https://x/cb"},
		"no redirect": {Issuer: "https://i", ClientID: "c"},
	} {
		if err := c.validate(); !errors.Is(err, ErrNotConfigured) {
			t.Fatalf("%s: got %v", name, err)
		}
	}
}
