package authz

import "testing"

// This table is transcribed from the roles matrix in the application design
// document, not from authz.go. If someone widens a role in the implementation,
// these assertions fail. That is the entire point of writing it out twice.
//
//	Role              | See | Policy | Lock | Ask wipe | Approve | Keys | Audit
//	Super Admin       |  Y  |   Y    |  Y   |    Y     |    Y    |  Y   |   Y
//	IT Admin          |  Y  |   Y    |  Y   |    Y     |    N    |  N   |   Y
//	Security Manager  |  Y  |   N    |  N   |    N     |    Y    |  Y   |   Y
//	Helpdesk          |  Y  |   N    |  N   |    N     |    N    |  N   |   N
//	Auditor           |  Y  |   N    |  N   |    N     |    N    |  N   |   Y
//	Employee          | own |   N    |  N   |    N     |    N    |  N   |   N
//	Platform operator |  N  |   N    |  N   |    N     |    N    |  N   |   N
func TestMatrixMatchesTheDesignDocument(t *testing.T) {
	expected := map[Role]map[Action]bool{
		SuperAdmin:      {ViewDevices: true, ChangePolicy: true, LockDevice: true, RequestWipe: true, ApproveWipe: true, RetrieveKey: true, ViewAudit: true, EnrolDevice: true, ManageAccess: true, NetworkRead: false, OffboardEmployee: true},
		ITAdmin:         {ViewDevices: true, ChangePolicy: true, LockDevice: true, RequestWipe: true, ApproveWipe: false, RetrieveKey: false, ViewAudit: true, EnrolDevice: true, ManageAccess: false, NetworkRead: false, OffboardEmployee: true},
		SecurityManager: {ViewDevices: true, ChangePolicy: false, LockDevice: false, RequestWipe: false, ApproveWipe: true, RetrieveKey: true, ViewAudit: true, EnrolDevice: false, ManageAccess: false, NetworkRead: false, OffboardEmployee: false},
		Helpdesk:        {ViewDevices: true, ChangePolicy: false, LockDevice: false, RequestWipe: false, ApproveWipe: false, RetrieveKey: false, ViewAudit: false, EnrolDevice: false, ManageAccess: false, NetworkRead: false, OffboardEmployee: false},
		Auditor:         {ViewDevices: true, ChangePolicy: false, LockDevice: false, RequestWipe: false, ApproveWipe: false, RetrieveKey: false, ViewAudit: true, EnrolDevice: false, ManageAccess: false, NetworkRead: false, OffboardEmployee: false},
		Employee:        {ViewDevices: false, ChangePolicy: false, LockDevice: false, RequestWipe: false, ApproveWipe: false, RetrieveKey: false, ViewAudit: false, EnrolDevice: false, ManageAccess: false, NetworkRead: false, OffboardEmployee: false},
		Operator:        {ViewDevices: false, ChangePolicy: false, LockDevice: false, RequestWipe: false, ApproveWipe: false, RetrieveKey: false, ViewAudit: false, EnrolDevice: false, ManageAccess: false, NetworkRead: false, OffboardEmployee: false},
		Bootstrap:       {ViewDevices: false, ChangePolicy: false, LockDevice: false, RequestWipe: false, ApproveWipe: false, RetrieveKey: false, ViewAudit: false, EnrolDevice: false, ManageAccess: false, NetworkRead: false, OffboardEmployee: false},
		Device:          {ViewDevices: false, ChangePolicy: false, LockDevice: false, RequestWipe: false, ApproveWipe: false, RetrieveKey: false, ViewAudit: false, EnrolDevice: false, ManageAccess: false, NetworkRead: false, OffboardEmployee: false},
		Network:         {ViewDevices: false, ChangePolicy: false, LockDevice: false, RequestWipe: false, ApproveWipe: false, RetrieveKey: false, ViewAudit: false, EnrolDevice: false, ManageAccess: false, NetworkRead: true, OffboardEmployee: false},
		HRFeed:          {ViewDevices: false, ChangePolicy: false, LockDevice: false, RequestWipe: false, ApproveWipe: false, RetrieveKey: false, ViewAudit: false, EnrolDevice: false, ManageAccess: false, NetworkRead: false, OffboardEmployee: true},
	}

	for role, actions := range expected {
		for action, want := range actions {
			if got := Can(role, action); got != want {
				t.Errorf("%s may %s: got %v, document says %v", role, action, got, want)
			}
		}
	}
}

// The separation that makes two approvals mean anything: nobody who can ask
// for a wipe can also approve one, except the Super Admin, and the setup
// wizard refuses to let one person hold both Super Admin and Security Manager.
func TestNobodyButSuperAdminCanBothRequestAndApproveAWipe(t *testing.T) {
	for _, r := range Roles() {
		if r == SuperAdmin {
			continue
		}
		if Can(r, RequestWipe) && Can(r, ApproveWipe) {
			t.Errorf("%s can both request and approve a wipe, which makes dual approval theatre", r)
		}
	}
}

func TestOperatorCanDoNothingToATenant(t *testing.T) {
	for _, a := range Actions() {
		if Can(Operator, a) {
			t.Errorf("the platform operator can %s inside a tenant", a)
		}
		// And the gateway's own bootstrap transactions may do nothing
		// through the matrix either: they read what a request needs
		// before anyone is signed in, and that is all.
		if Can(Bootstrap, a) {
			t.Errorf("a bootstrap transaction can %s", a)
		}
	}
}

// Every role must have an explicit answer for every action. A role that falls
// through to a default is a role nobody decided about.
func TestMatrixIsTotal(t *testing.T) {
	for _, r := range Roles() {
		actions, ok := matrix[r]
		if !ok {
			t.Fatalf("role %s is not in the matrix", r)
		}
		for _, a := range Actions() {
			if _, present := actions[a]; !present {
				t.Errorf("role %s has no entry for action %s", r, a)
			}
		}
	}
}

func TestUnknownRoleIsRefusedRatherThanDefaulted(t *testing.T) {
	if _, err := Parse("administrator"); err == nil {
		t.Fatal("an unknown role parsed successfully")
	}
	for _, a := range Actions() {
		if Can(Role("administrator"), a) {
			t.Errorf("an unknown role was allowed to %s", a)
		}
	}
}

// Every role a person can sign in as may enrol their own phone, and nothing
// else may. The action is narrow because the handler takes the address from
// the session, so holding it lets a person do one thing, to themselves.
func TestOnlyPeopleMayEnrolTheirOwnPhone(t *testing.T) {
	people := map[Role]bool{SuperAdmin: true, ITAdmin: true, SecurityManager: true, Helpdesk: true, Auditor: true, Employee: true}
	for _, r := range Roles() {
		if got := Can(r, EnrolOwn); got != people[r] {
			t.Errorf("%s may enrol their own phone: got %v, want %v", r, got, people[r])
		}
	}
	// Holding it never grants the wider one.
	if Can(Employee, EnrolDevice) {
		t.Error("an Employee holds device.enrol, which invites a device for anyone")
	}
}
