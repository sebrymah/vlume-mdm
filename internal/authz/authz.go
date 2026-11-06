// Package authz is the single place that answers "may this role do this".
//
// Requirement R12: least-privilege access control enforced in every service,
// as one implementation consulted by all of them rather than twelve copies
// that drift. Requirement F16: six tenant roles, plus the platform operator,
// whose every answer here is no.
//
// The matrix below is the one in the application design document. It is
// duplicated in authz_test.go on purpose: the test is written from the
// document rather than from this file, so an edit that quietly widens a role
// fails the build instead of shipping.
package authz

import "fmt"

type Role string

const (
	SuperAdmin      Role = "super_admin"
	ITAdmin         Role = "it_admin"
	SecurityManager Role = "security_manager"
	Helpdesk        Role = "helpdesk"
	Auditor         Role = "auditor"
	Employee        Role = "employee"
	// Operator is the platform operator. It is listed here so that every
	// answer it gets is an explicit no rather than an unhandled case.
	Operator Role = "platform_operator"
	// Bootstrap is the gateway's own transactions: resolving a device
	// certificate, redeeming an enrolment, reading a tenant's brand or
	// role map before anyone is signed in. It may do nothing through the
	// matrix. It exists because such a transaction is neither a person nor
	// the operator: until 0042 these used the employee role as "can do
	// almost nothing", and once the database held an employee to their
	// own devices, a transaction that was nobody's could see no device.
	Bootstrap Role = "bootstrap"
	// Device is a managed machine presenting its own identity certificate.
	//
	// It is NOT a person and it is not an administrator. Until the agent
	// sprint a device certificate was resolved as ITAdmin, which meant one
	// stolen laptop could lock any device in the tenant, request a wipe of
	// any device, rewrite the policy and mint enrolment tokens. The list
	// below is what a device actually needs: see its own things, and
	// nothing else. The handlers it reaches narrow that further to the one
	// device the certificate names.
	Device Role = "device"
	// Network is a tenant's own network equipment, holding an integration
	// token: a Wi-Fi controller, VPN concentrator or NAC asking whether a
	// device may be let in. It can read the access feed and nothing else.
	// Like Device, it is not a person and is not selectable by the
	// identity provider.
	Network Role = "network"
	// HRFeed is the tenant's HR system, holding an integration token with
	// the hr scope. It may say that a person has left, and nothing else.
	HRFeed Role = "hr_feed"
)

type Action string

const (
	ViewDevices    Action = "devices.view"
	ViewOwnDevices Action = "devices.view_own"
	ChangePolicy   Action = "policy.change"
	LockDevice     Action = "device.lock"
	RequestWipe    Action = "wipe.request"
	ApproveWipe    Action = "wipe.approve"
	RetrieveKey    Action = "key.retrieve"
	ViewAudit      Action = "audit.view"
	// EnrolDevice admits a NEW device into the tenant.
	//
	// A new action rather than a reused one, and the standing rule says to
	// write down why. No existing action covers it: devices.view is
	// read-only, policy.change is about policy, and the wipe actions are
	// about devices already here. Admitting a machine is its own
	// capability, and the matrix has to be literally true or it is not
	// worth reading. Helpdesk in particular should keep seeing devices
	// while not being able to admit them.
	EnrolDevice Action = "device.enrol"
	// ManageAccess decides who gets in and as what: the identity provider
	// and the group-to-role mapping.
	//
	// A new action, and the only one held by Super Admin alone, with the
	// written reason the standing rule asks for. Anybody who can edit the
	// role map can map their own group to super_admin, so editing it has
	// to be gated to people who already are. No existing action is that
	// narrow: policy.change is IT Admin's too, and an IT Admin who can
	// promote themselves is a Super Admin with extra steps.
	ManageAccess Action = "access.manage"
	// NetworkRead is the access feed: may this device be let onto the
	// network. A new action with the written reason the standing rule
	// asks for: devices.view returns names, owners, lost reports and
	// findings, and the thing holding this credential is a piece of
	// network equipment that needs one bit per device. The narrowest
	// existing action is still far too wide.
	NetworkRead Action = "network.read"
	// OffboardEmployee is "this person has left": every device assigned
	// to them is wiped of work data and retired. Held by the roles that
	// may request a wipe, and by the HR feed, which may do nothing else.
	// Its own action because the HR feed must not hold wipe.request: that
	// would let an HR integration erase a named device on demand.
	OffboardEmployee Action = "offboard.employee"
)

var matrix = map[Role]map[Action]bool{
	SuperAdmin: {
		ManageAccess: true,
		ViewDevices:  true, ViewOwnDevices: true, ChangePolicy: true,
		LockDevice: true, RequestWipe: true, ApproveWipe: true,
		RetrieveKey: true, ViewAudit: true,
		EnrolDevice: true, NetworkRead: false, OffboardEmployee: true,
	},
	ITAdmin: {
		ManageAccess: false,
		ViewDevices:  true, ViewOwnDevices: true, ChangePolicy: true,
		LockDevice: true, RequestWipe: true, ApproveWipe: false,
		RetrieveKey: false, ViewAudit: true,
		EnrolDevice: true, NetworkRead: false, OffboardEmployee: true,
	},
	SecurityManager: {
		ManageAccess: false,
		ViewDevices:  true, ViewOwnDevices: true, ChangePolicy: false,
		LockDevice: false, RequestWipe: false, ApproveWipe: true,
		RetrieveKey: true, ViewAudit: true,
		EnrolDevice: false, NetworkRead: false, OffboardEmployee: false,
	},
	Helpdesk: {
		ManageAccess: false,
		ViewDevices:  true, ViewOwnDevices: true, ChangePolicy: false,
		LockDevice: false, RequestWipe: false, ApproveWipe: false,
		RetrieveKey: false, ViewAudit: false,
		EnrolDevice: false, NetworkRead: false, OffboardEmployee: false,
	},
	Auditor: {
		ManageAccess: false,
		ViewDevices:  true, ViewOwnDevices: true, ChangePolicy: false,
		LockDevice: false, RequestWipe: false, ApproveWipe: false,
		RetrieveKey: false, ViewAudit: true,
		EnrolDevice: false, NetworkRead: false, OffboardEmployee: false,
	},
	Employee: {
		ManageAccess: false,
		ViewDevices:  false, ViewOwnDevices: true, ChangePolicy: false,
		LockDevice: false, RequestWipe: false, ApproveWipe: false,
		RetrieveKey: false, ViewAudit: false,
		EnrolDevice: false, NetworkRead: false, OffboardEmployee: false,
	},
	Operator: {
		ManageAccess: false,
		ViewDevices:  false, ViewOwnDevices: false, ChangePolicy: false,
		LockDevice: false, RequestWipe: false, ApproveWipe: false,
		RetrieveKey: false, ViewAudit: false,
		EnrolDevice: false, NetworkRead: false, OffboardEmployee: false,
	},
	Bootstrap: {
		ManageAccess: false,
		ViewDevices:  false, ViewOwnDevices: false, ChangePolicy: false,
		LockDevice: false, RequestWipe: false, ApproveWipe: false,
		RetrieveKey: false, ViewAudit: false,
		EnrolDevice: false, NetworkRead: false, OffboardEmployee: false,
	},
	Device: {
		ManageAccess: false,
		ViewDevices:  false, ViewOwnDevices: true, ChangePolicy: false,
		LockDevice: false, RequestWipe: false, ApproveWipe: false,
		RetrieveKey: false, ViewAudit: false,
		EnrolDevice: false, NetworkRead: false, OffboardEmployee: false,
	},
	Network: {
		ManageAccess: false,
		ViewDevices:  false, ViewOwnDevices: false, ChangePolicy: false,
		LockDevice: false, RequestWipe: false, ApproveWipe: false,
		RetrieveKey: false, ViewAudit: false,
		EnrolDevice: false, NetworkRead: true, OffboardEmployee: false,
	},
	HRFeed: {
		ManageAccess: false,
		ViewDevices:  false, ViewOwnDevices: false, ChangePolicy: false,
		LockDevice: false, RequestWipe: false, ApproveWipe: false,
		RetrieveKey: false, ViewAudit: false,
		EnrolDevice: false, NetworkRead: false, OffboardEmployee: true,
	},
}

// Can is the only way to ask. An unknown role answers no, so a role that is
// added to the identity provider but not to this matrix locks its holders out
// rather than letting them through.
func Can(r Role, a Action) bool {
	actions, ok := matrix[r]
	if !ok {
		return false
	}
	return actions[a]
}

// Parse refuses anything not in the matrix. A role string arriving from an
// identity provider is untrusted input like any other.
func Parse(s string) (Role, error) {
	r := Role(s)
	if _, ok := matrix[r]; !ok {
		return "", fmt.Errorf("authz: unknown role %q", s)
	}
	return r, nil
}

// Roles returns every role, for tests and for the console's own roles page.
func Roles() []Role {
	return []Role{SuperAdmin, ITAdmin, SecurityManager, Helpdesk, Auditor, Employee,
		Operator, Bootstrap, Device, Network, HRFeed}
}

// Actions returns every action, so a test can assert the matrix is total:
// every role has an explicit answer for every action, and nothing falls
// through to a default.
func Actions() []Action {
	return []Action{
		ViewDevices, ViewOwnDevices, ChangePolicy, LockDevice,
		RequestWipe, ApproveWipe, RetrieveKey, ViewAudit, EnrolDevice,
		ManageAccess, NetworkRead, OffboardEmployee,
	}
}
