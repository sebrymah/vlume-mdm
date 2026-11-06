package authz

// Rank orders the roles by how much they can do, so that code with a set of
// roles and one slot to fill can pick without inventing its own ordering.
//
// There is exactly one caller today and it is the reason this exists: people
// are in many groups at the identity provider, those groups map to roles, and
// a person in both "IT" and "All Staff" has to end up somewhere. They end up
// at the higher rank, because the alternative is an IT administrator who
// cannot do their job on alternate Tuesdays depending on map iteration order.
//
// Rank is NOT a substitute for Can. A higher rank does not imply a superset
// of another role's permissions and the matrix says so: a Security Manager
// approves wipes and cannot request one, an IT Admin is the reverse. Asking
// "is this role at least X" to decide an action would be wrong. The only
// correct question about an action is Can.
func Rank(r Role) int {
	switch r {
	case SuperAdmin:
		return 60
	case SecurityManager:
		return 50
	case ITAdmin:
		return 40
	case Auditor:
		return 30
	case Helpdesk:
		return 20
	case Employee:
		return 10
	default:
		// Operator, Device and anything unknown. None of them is ever
		// selectable by the rule above, which is the intent: neither the
		// platform operator's role nor a managed device's is something a
		// tenant's identity provider can hand out.
		return 0
	}
}

// FromTenantIdentity reports whether a role may be given to a person by a
// tenant's own identity provider.
//
// The database says the same thing in a CHECK constraint on tenant_role_map.
// Both are kept, because the constraint protects the stored mapping and this
// protects the decision, and they fail at different times: one when an
// administrator saves a bad mapping, one when a token arrives carrying a
// group we would otherwise honour.
func FromTenantIdentity(r Role) bool {
	// Neither the platform operator nor a managed device is a role a
	// tenant's identity provider can hand to a person.
	if r == Operator || r == Device || r == Network || r == HRFeed {
		return false
	}
	_, ok := matrix[r]
	return ok
}
