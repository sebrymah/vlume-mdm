package android

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2/jwt"

	"platform/internal/policy"
)

// AMAPI is the real client: a thin REST client over the Android Management
// API v1, authenticated as the operator's service account. It is deliberately
// thin, so that the fake in fake.go can implement the same seven calls and
// a test can prove the request shapes rather than the client library.
type AMAPI struct {
	base   string
	client *http.Client
	// project is the Google Cloud project the service account belongs to.
	// Google wants it named on the two calls that create something outside
	// any enterprise (a sign-up URL, an enterprise), because those are
	// billed and quota'd to a project, not to the account making the call.
	project string
}

// ServiceAccount is the part of Google's service-account JSON this needs.
type ServiceAccount struct {
	ProjectID   string `json:"project_id"`
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri"`
}

const scope = "https://www.googleapis.com/auth/androidmanagement"

// NewAMAPI builds the client from the service account's JSON.
func NewAMAPI(ctx context.Context, credentialsJSON []byte) (*AMAPI, error) {
	var sa ServiceAccount
	if err := json.Unmarshal(credentialsJSON, &sa); err != nil {
		return nil, fmt.Errorf("android: the credentials file is not a service account: %w", err)
	}
	if sa.ClientEmail == "" || sa.PrivateKey == "" {
		return nil, errors.New("android: the credentials file has no client_email or private_key")
	}
	if sa.ProjectID == "" {
		return nil, errors.New("android: the credentials file names no project_id, and Google refuses a sign-up without one")
	}
	if sa.TokenURI == "" {
		sa.TokenURI = "https://oauth2.googleapis.com/token"
	}
	cfg := &jwt.Config{
		Email: sa.ClientEmail, PrivateKey: []byte(sa.PrivateKey),
		Scopes: []string{scope}, TokenURL: sa.TokenURI,
	}
	return &AMAPI{
		base:    "https://androidmanagement.googleapis.com/v1",
		client:  cfg.Client(ctx),
		project: sa.ProjectID,
	}, nil
}

// NewAMAPIAt points the same client at another base, with its own
// transport: the fake in tests and in the demonstration.
func NewAMAPIAt(base string, client *http.Client) *AMAPI {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &AMAPI{base: strings.TrimSuffix(base, "/"), client: client, project: "fake-project"}
}

func (a *AMAPI) Name() string { return "Android Management API" }

type apiError struct {
	Status int
	Body   string
}

// Error reads Google's answer as a sentence when it is one. Google's
// errors are a JSON envelope with a message, a status word and a reason;
// the person who sees it on the Android page is an administrator with an
// API to switch on, not a developer with a body to parse. The whole body
// is kept for the log, and shown as it came when it is not that envelope.
func (e apiError) Error() string {
	var g struct {
		Error struct {
			Message string `json:"message"`
			Status  string `json:"status"`
			Details []struct {
				Reason string `json:"reason"`
			} `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal([]byte(e.Body), &g) == nil && g.Error.Message != "" {
		why := g.Error.Status
		for _, d := range g.Error.Details {
			if d.Reason != "" {
				why += ", " + d.Reason
				break
			}
		}
		msg := g.Error.Message
		// Some refusals carry a Java stack trace after the words. The
		// words are for the administrator; the trace is for nobody here.
		if i := strings.Index(msg, "debug_info:"); i > 0 {
			msg = strings.TrimSpace(msg[:i])
		}
		return fmt.Sprintf("android: Google refused (%d %s): %s", e.Status, why, msg)
	}
	return fmt.Sprintf("android: Google answered %d: %s", e.Status, e.Body)
}

func (a *AMAPI) call(ctx context.Context, method, path string, query url.Values, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	u := a.base + "/" + strings.TrimPrefix(path, "/")
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("android: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return apiError{Status: resp.StatusCode, Body: strings.TrimSpace(string(raw))}
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func (a *AMAPI) CreateSignupURL(ctx context.Context, callbackURL string) (SignupURL, error) {
	var out struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	q := url.Values{"projectId": {a.project}, "callbackUrl": {callbackURL}}
	if err := a.call(ctx, "POST", "signupUrls", q, nil, &out); err != nil {
		return SignupURL{}, err
	}
	return SignupURL{Name: out.Name, URL: out.URL}, nil
}

func (a *AMAPI) CreateEnterprise(ctx context.Context, signupURLName, enterpriseToken, displayName string) (Enterprise, error) {
	var out struct {
		Name        string `json:"name"`
		DisplayName string `json:"enterpriseDisplayName"`
	}
	q := url.Values{"projectId": {a.project}, "signupUrlName": {signupURLName}, "enterpriseToken": {enterpriseToken}}
	in := map[string]any{"enterpriseDisplayName": displayName}
	if err := a.call(ctx, "POST", "enterprises", q, in, &out); err != nil {
		return Enterprise{}, err
	}
	return Enterprise{Name: out.Name, DisplayName: out.DisplayName}, nil
}

func (a *AMAPI) DeleteEnterprise(ctx context.Context, enterprise string) error {
	return a.call(ctx, "DELETE", enterprise, nil, nil, nil)
}

func (a *AMAPI) ApplyPolicy(ctx context.Context, enterprise, policyID string, body Policy) error {
	return a.call(ctx, "PATCH", enterprise+"/policies/"+policyID, nil, body, nil)
}

func (a *AMAPI) CreateEnrollmentToken(ctx context.Context, enterprise string, in TokenInput) (EnrollmentToken, error) {
	var out struct {
		Name           string `json:"name"`
		Value          string `json:"value"`
		QRCode         string `json:"qrCode"`
		ExpirationTime string `json:"expirationTimestamp"`
	}
	req := map[string]any{"policyName": in.PolicyName}
	if in.Lifetime > 0 {
		req["duration"] = fmt.Sprintf("%ds", int(in.Lifetime.Seconds()))
	}
	if in.User != "" {
		req["user"] = map[string]any{"accountIdentifier": in.User}
	}
	if in.OneTime {
		req["oneTimeOnly"] = true
	}
	if in.PersonalUsage {
		req["allowPersonalUsage"] = "PERSONAL_USAGE_ALLOWED"
	} else {
		req["allowPersonalUsage"] = "PERSONAL_USAGE_DISALLOWED"
	}
	if err := a.call(ctx, "POST", enterprise+"/enrollmentTokens", nil, req, &out); err != nil {
		return EnrollmentToken{}, err
	}
	// Google's field is expirationTimestamp. The first real token came back
	// with an expiry of the year 1, because the client read a field Google
	// does not send and the fake had agreed with the client; the fake now
	// sends Google's name. If the field is ever missing, the lifetime we
	// asked for is a better answer than a date nobody meant.
	exp, err := time.Parse(time.RFC3339, out.ExpirationTime)
	if err != nil && in.Lifetime > 0 {
		exp = time.Now().UTC().Add(in.Lifetime)
	}
	return EnrollmentToken{Name: out.Name, Value: out.Value, QRCode: out.QRCode, ExpiresAt: exp}, nil
}

// wireDevice is Google's device resource, the parts we read.
type wireDevice struct {
	Name                string `json:"name"`
	State               string `json:"state"`
	EnrollmentTokenName string `json:"enrollmentTokenName"`
	PolicyName          string `json:"policyName"`
	LastStatusReport    string `json:"lastStatusReportTime"`
	PolicyCompliant     bool   `json:"policyCompliant"`
	HardwareInfo        struct {
		SerialNumber string `json:"serialNumber"`
		Model        string `json:"model"`
	} `json:"hardwareInfo"`
	SoftwareInfo struct {
		AndroidVersion string `json:"androidVersion"`
		// SecurityPatchLevel is the date of the phone's security patch.
		SecurityPatchLevel string `json:"securityPatchLevel"`
	} `json:"softwareInfo"`
	DeviceSettings *wireSettings `json:"deviceSettings"`
	// SecurityPosture is Google's own reading of how safe the phone is.
	SecurityPosture      *wirePosture `json:"securityPosture"`
	NonComplianceDetails []struct {
		SettingName string `json:"settingName"`
		Reason      string `json:"nonComplianceReason"`
	} `json:"nonComplianceDetails"`
	ApplicationReports []struct {
		PackageName string `json:"packageName"`
		DisplayName string `json:"displayName"`
		VersionName string `json:"versionName"`
	} `json:"applicationReports"`
}

// wireSettings is the part of a device report that says how it is set. The
// switches are pointers because "Google did not say" is not "it is off".
type wireSettings struct {
	IsDeviceSecure             bool   `json:"isDeviceSecure"`
	IsEncrypted                bool   `json:"isEncrypted"`
	VerifiedBootState          string `json:"verifiedBootState"`
	ADBEnabled                 *bool  `json:"adbEnabled"`
	DevelopmentSettingsEnabled *bool  `json:"developmentSettingsEnabled"`
	VerifyAppsEnabled          *bool  `json:"verifyAppsEnabled"`
	UnknownSourcesEnabled      *bool  `json:"unknownSourcesEnabled"`
}

type wirePosture struct {
	DevicePosture string `json:"devicePosture"` // SECURE, AT_RISK, POTENTIAL_RISK
}

func (d wireDevice) device() Device {
	out := Device{
		Name: d.Name, EnrollmentToken: d.EnrollmentTokenName, State: d.State, PolicyName: d.PolicyName,
		Serial: d.HardwareInfo.SerialNumber, Model: d.HardwareInfo.Model,
		AndroidVersion: d.SoftwareInfo.AndroidVersion, Compliant: d.PolicyCompliant,
		PatchLevel: d.SoftwareInfo.SecurityPatchLevel,
	}
	if d.SecurityPosture != nil {
		out.Posture = d.SecurityPosture.DevicePosture
	}
	if d.DeviceSettings != nil {
		out.ADBEnabled, out.DevSettingsEnabled = d.DeviceSettings.ADBEnabled, d.DeviceSettings.DevelopmentSettingsEnabled
		out.VerifyApps, out.UnknownSources = d.DeviceSettings.VerifyAppsEnabled, d.DeviceSettings.UnknownSourcesEnabled
		secure, enc := d.DeviceSettings.IsDeviceSecure, d.DeviceSettings.IsEncrypted
		out.Secure, out.Encrypted = &secure, &enc
		switch d.DeviceSettings.VerifiedBootState {
		case "VERIFIED":
			v := true
			out.VerifiedBoot = &v
		case "UNVERIFIED":
			v := false
			out.VerifiedBoot = &v
		}
	}
	if t, err := time.Parse(time.RFC3339, d.LastStatusReport); err == nil {
		out.LastReportAt = &t
	}
	for _, n := range d.NonComplianceDetails {
		out.NonCompliance = append(out.NonCompliance, n.SettingName+": "+n.Reason)
	}
	for _, a := range d.ApplicationReports {
		name := a.DisplayName
		if name == "" {
			name = a.PackageName
		}
		out.Apps = append(out.Apps, policy.App{Identifier: a.PackageName, Name: name, Version: a.VersionName})
	}
	return out
}

func (a *AMAPI) ListDevices(ctx context.Context, enterprise string) ([]Device, error) {
	var all []Device
	token := ""
	for {
		var out struct {
			Devices       []wireDevice `json:"devices"`
			NextPageToken string       `json:"nextPageToken"`
		}
		q := url.Values{"pageSize": {"100"}}
		if token != "" {
			q.Set("pageToken", token)
		}
		if err := a.call(ctx, "GET", enterprise+"/devices", q, nil, &out); err != nil {
			return nil, err
		}
		for _, d := range out.Devices {
			all = append(all, d.device())
		}
		if out.NextPageToken == "" {
			return all, nil
		}
		token = out.NextPageToken
	}
}

func (a *AMAPI) IssueCommand(ctx context.Context, device string, cmd Command) error {
	in := map[string]any{"type": string(cmd)}
	if cmd == Lock {
		in["duration"] = "60s"
	}
	return a.call(ctx, "POST", device+":issueCommand", nil, in, nil)
}

func (a *AMAPI) StartLostMode(ctx context.Context, device string, in LostModeInput) error {
	params := map[string]any{
		"lostMessage": map[string]any{"defaultMessage": in.Message},
	}
	if in.Organisation != "" {
		params["lostOrganization"] = map[string]any{"defaultMessage": in.Organisation}
	}
	if in.Email != "" {
		params["lostEmailAddress"] = in.Email
	}
	if in.Phone != "" {
		params["lostPhoneNumber"] = map[string]any{"defaultMessage": in.Phone}
	}
	return a.call(ctx, "POST", device+":issueCommand", nil,
		map[string]any{"type": "START_LOST_MODE", "startLostModeParams": params}, nil)
}

func (a *AMAPI) StopLostMode(ctx context.Context, device string) error {
	return a.call(ctx, "POST", device+":issueCommand", nil,
		map[string]any{"type": "STOP_LOST_MODE", "stopLostModeParams": map[string]any{}}, nil)
}

func (a *AMAPI) Wipe(ctx context.Context, device string, keepPersonal bool) error {
	q := url.Values{}
	if !keepPersonal {
		// A full wipe takes the external storage too. Factory reset
		// protection is left as Google defaults it, which keeps a wiped
		// device tied to the account that managed it: right for a lost
		// device, and the reason a re-issued one is wiped selectively.
		q["wipeDataFlags"] = []string{"WIPE_EXTERNAL_STORAGE"}
	}
	return a.call(ctx, "DELETE", device, q, nil, nil)
}
