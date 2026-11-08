// Package android is the Android Enterprise adapter: the one place Google's
// Android Management API lands.
//
// Everything above it is built and tested against a fake of that API. The
// real client is written and compiles, and nothing deployed can use it until
// the operator has a service account for the API, which is configuration
// rather than code. Until then the platform refuses Android binding with
// the reason, and the setup checklist says so.
//
// The shape of the dependency: ONE service account for the platform, held
// by the operator; ONE enterprise per tenant, bound by that tenant's own
// administrator signing in with a Google account; policies, enrolment
// tokens and commands all addressed under the tenant's enterprise. The
// adapter never sees a tenant id: the caller passes the enterprise name,
// and the enterprise name came from the tenant's own row.
package android

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"platform/internal/policy"
)

var ErrNotConfigured = errors.New("android: the Android Management API is not configured")

// EnrolLink is Google's own enrolment link for a token: opened on the phone,
// it installs Android Device Policy from Google Play and enrols with the
// token. It is Google's address, not this console's, because the phone
// talks to Google and never to us; a link to our hostname would be a link
// to nothing the phone can use.
func EnrolLink(tokenValue string) string {
	return "https://enterprise.google.com/android/enroll?et=" + url.QueryEscape(tokenValue)
}

type SignupURL struct {
	Name string // signupUrls/… , needed to finish the binding
	URL  string // where to send the administrator
}

type Enterprise struct {
	Name        string // enterprises/LC…
	DisplayName string
}

type TokenInput struct {
	PolicyName string // enterprises/X/policies/default
	// User is Google's accountIdentifier: who the device is for. Carried
	// so a device that enrols with this token lands on that person's page.
	User     string
	Lifetime time.Duration
	// OneTime tokens are spent on first use. Everything this platform
	// hands out is one-time, as the enrolment links are.
	OneTime bool
	// PersonalUsage says the device is the person's own (F2, F10): the
	// enrolment makes a WORK PROFILE beside their personal space, and
	// nothing this platform does reaches outside it. Company-owned
	// devices are fully managed instead.
	PersonalUsage bool
}

type EnrollmentToken struct {
	Name      string
	Value     string
	QRCode    string // the JSON a provisioning QR carries
	ExpiresAt time.Time
}

// Device is what Google tells us about one enrolled device. The fields are
// the ones the compliance engine can judge from; anything else Google
// knows stays with Google.
type Device struct {
	Name string // enterprises/X/devices/Y
	// PolicyName is the Google policy the phone was given, which says
	// whether it is judged as a company phone or a work profile.
	PolicyName      string
	EnrollmentToken string // the token's name, to match who it was for
	Serial          string
	Model           string
	AndroidVersion  string
	// Nil means Google did not say, which the engine treats as unknown.
	Secure    *bool // a screen lock is set
	Encrypted *bool
	// VerifiedBoot is Google's root check: true when the boot chain
	// verified, false when it did not, nil when Google did not say.
	VerifiedBoot *bool
	// Compliant is Google's own verdict against the policy we delivered,
	// with the settings it names as out of line.
	Compliant     bool
	NonCompliance []string
	// Apps is what Google reports installed, when the policy asks it to.
	Apps         []policy.App
	LastReportAt *time.Time
	State        string // ACTIVE, DISABLED, DELETED, PROVISIONING
}

type Command string

const (
	Lock          Command = "LOCK"
	ResetPassword Command = "RESET_PASSWORD"
	Reboot        Command = "REBOOT"
)

// LostModeInput is what the lock screen says while the device is lost. It
// is the tenant's words and the tenant's name: a found phone shows who it
// belongs to, never who runs the platform.
type LostModeInput struct {
	Message      string
	Organisation string
	Email        string
	Phone        string
}

// Provider is the port. Two implementations: the real API, and the fake
// the tests and the demonstration run against.
type Provider interface {
	Name() string
	CreateSignupURL(ctx context.Context, callbackURL string) (SignupURL, error)
	CreateEnterprise(ctx context.Context, signupURLName, enterpriseToken, displayName string) (Enterprise, error)
	DeleteEnterprise(ctx context.Context, enterprise string) error
	ApplyPolicy(ctx context.Context, enterprise, policyID string, body Policy) error
	CreateEnrollmentToken(ctx context.Context, enterprise string, in TokenInput) (EnrollmentToken, error)
	ListDevices(ctx context.Context, enterprise string) ([]Device, error)
	IssueCommand(ctx context.Context, device string, cmd Command) error
	StartLostMode(ctx context.Context, device string, in LostModeInput) error
	StopLostMode(ctx context.Context, device string) error
	// Wipe removes the device from management. keepPersonal is the work
	// profile case: the profile goes, the person's own data stays.
	Wipe(ctx context.Context, device string, keepPersonal bool) error
}

// NotConfigured is the honest stand-in: every call refuses with the reason.
type NotConfigured struct{}

func (NotConfigured) Name() string { return "Android Management API (not configured)" }

func (NotConfigured) why() error {
	return fmt.Errorf("%w: the operator has not provided a service account "+
		"(MDM_ANDROID_CREDENTIALS_FILE) for Google's Android Management API", ErrNotConfigured)
}
func (n NotConfigured) CreateSignupURL(context.Context, string) (SignupURL, error) {
	return SignupURL{}, n.why()
}
func (n NotConfigured) CreateEnterprise(context.Context, string, string, string) (Enterprise, error) {
	return Enterprise{}, n.why()
}
func (n NotConfigured) DeleteEnterprise(context.Context, string) error { return n.why() }
func (n NotConfigured) ApplyPolicy(context.Context, string, string, Policy) error {
	return n.why()
}
func (n NotConfigured) CreateEnrollmentToken(context.Context, string, TokenInput) (EnrollmentToken, error) {
	return EnrollmentToken{}, n.why()
}
func (n NotConfigured) ListDevices(context.Context, string) ([]Device, error) { return nil, n.why() }
func (n NotConfigured) IssueCommand(context.Context, string, Command) error   { return n.why() }
func (n NotConfigured) StartLostMode(context.Context, string, LostModeInput) error {
	return n.why()
}
func (n NotConfigured) StopLostMode(context.Context, string) error { return n.why() }
func (n NotConfigured) Wipe(context.Context, string, bool) error   { return n.why() }

// Configured says whether a provider can be used, so the console can show
// a blocked step rather than a button that fails.
func Configured(p Provider) bool {
	if p == nil {
		return false
	}
	_, isNot := p.(NotConfigured)
	return !isNot
}
