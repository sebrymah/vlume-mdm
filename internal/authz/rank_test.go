package authz

import "testing"

// The ordering, written from the application design document rather than
// from rank.go, for the same reason the matrix is: an edit that quietly
// promotes a role has to fail the build.
func TestTheRankOrderIsTheOneInTheDesign(t *testing.T) {
	order := []Role{Employee, Helpdesk, Auditor, ITAdmin, SecurityManager, SuperAdmin}
	for i := 1; i < len(order); i++ {
		if Rank(order[i]) <= Rank(order[i-1]) {
			t.Fatalf("%s does not outrank %s", order[i], order[i-1])
		}
	}
}

// Rank is for choosing between roles, never for deciding an action. The
// matrix is not a ladder, and these two pairs are the proof: each outranks
// the other on something.
func TestRankIsNotASubstituteForTheMatrix(t *testing.T) {
	if Rank(SecurityManager) <= Rank(ITAdmin) {
		t.Fatal("the premise of this test has changed")
	}
	if Can(SecurityManager, RequestWipe) {
		t.Fatal("a Security Manager may request a wipe, so the separation is gone")
	}
	if !Can(ITAdmin, RequestWipe) {
		t.Fatal("an IT Admin may not request a wipe")
	}
	// The higher rank cannot do something the lower one can, which is
	// exactly why asking "is this role at least X" would be wrong.
	if !Can(ITAdmin, ChangePolicy) || Can(SecurityManager, ChangePolicy) {
		t.Fatal("policy change is no longer split the way the design says")
	}
}

// Nothing a tenant's identity provider can say makes someone the platform
// operator, and an unknown role ranks below everyone rather than above.
func TestTheOperatorAndTheUnknownRankLowest(t *testing.T) {
	if Rank(Operator) != 0 {
		t.Fatalf("the platform operator ranks %d", Rank(Operator))
	}
	if Rank(Role("something-new")) != 0 {
		t.Fatal("an unknown role ranks above the floor")
	}
	for _, r := range []Role{Employee, Helpdesk, Auditor, ITAdmin, SecurityManager, SuperAdmin} {
		if Rank(r) <= Rank(Operator) {
			t.Fatalf("%s does not outrank the platform operator", r)
		}
	}
}

func TestOnlyTenantRolesCanComeFromAnIdentityProvider(t *testing.T) {
	for _, r := range []Role{SuperAdmin, ITAdmin, SecurityManager, Helpdesk, Auditor, Employee} {
		if !FromTenantIdentity(r) {
			t.Fatalf("%s cannot be granted by a tenant", r)
		}
	}
	if FromTenantIdentity(Operator) {
		t.Fatal("a tenant can grant the platform operator role")
	}
	if FromTenantIdentity(Role("it_admin ")) {
		t.Fatal("a role name with whitespace was accepted")
	}
	if FromTenantIdentity(Role("")) {
		t.Fatal("an empty role was accepted")
	}
}
