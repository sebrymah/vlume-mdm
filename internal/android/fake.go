package android

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"
)

// FakeGoogle stands in for the Android Management API: the same seven
// calls, over HTTP, with enough behaviour to prove the client's request
// shapes and to let the demonstration bind an enterprise and enrol a
// device with no Google account in the room.
//
// It records what it was asked, so a test can assert that a selective wipe
// did not carry the full-wipe flags, which is the kind of thing that is
// only ever wrong on the day somebody presses the button.
type FakeGoogle struct {
	srv    *httptest.Server
	public string

	mu          sync.Mutex
	signups     map[string]string // name -> callback
	enterprises map[string]*fakeEnterprise
	// Calls is every request, method and path, in order.
	Calls []string
	// Wipes records the flags each wipe carried, by device name.
	Wipes map[string][]string
	// Commands records each issued command by device name.
	Commands map[string][]string
	// LostMessages records the lock-screen message of the last lost mode
	// per device, so a test can read whose name a found phone shows.
	LostMessages map[string]string
	// Policies records the last policy body applied per enterprise/policy.
	Policies map[string]Policy
	// TokenUsage records allowPersonalUsage per token name: the difference
	// between a work profile and a fully managed device.
	TokenUsage map[string]string
	// FailTokens makes the next enrolment-token requests fail, the way Google
	// does on a bad day, so a test can see what the platform does about it.
	FailTokens bool
}

type fakeEnterprise struct {
	name    string
	display string
	tokens  map[string]fakeToken
	devices map[string]wireDevice
}

type fakeToken struct {
	value    string
	user     string
	policy   string
	personal string // allowPersonalUsage as asked
}

func newFake() *FakeGoogle {
	return &FakeGoogle{
		signups: map[string]string{}, enterprises: map[string]*fakeEnterprise{},
		Wipes: map[string][]string{}, Commands: map[string][]string{}, Policies: map[string]Policy{},
		LostMessages: map[string]string{}, TokenUsage: map[string]string{},
	}
}

func NewFakeGoogle() *FakeGoogle {
	f := newFake()
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	f.public = f.srv.URL
	return f
}

// NewFakeGoogleOn listens on a fixed address and advertises publicURL in
// the sign-up links it hands out, so a browser outside the process (the
// demonstration's) can reach the pretend sign-in page.
func NewFakeGoogleOn(addr, publicURL string) (*FakeGoogle, error) {
	f := newFake()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	f.srv = &httptest.Server{Listener: ln, Config: &http.Server{Handler: http.HandlerFunc(f.serve),
		ReadHeaderTimeout: 10 * time.Second}}
	f.srv.Start()
	f.public = strings.TrimSuffix(publicURL, "/")
	return f, nil
}

func (f *FakeGoogle) Close()         { f.srv.Close() }
func (f *FakeGoogle) URL() string    { return f.public }
func (f *FakeGoogle) Client() *AMAPI { return NewAMAPIAt(f.public, f.srv.Client()) }

func randomID(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return strings.Map(func(r rune) rune {
		if r == '-' || r == '_' {
			return 'x'
		}
		return r
	}, base64.RawURLEncoding.EncodeToString(b))
}

// EnterpriseToken is what Google's sign-up page hands back on the callback.
// The fake accepts any token for a signup URL it issued; a real one is a
// one-time value tied to the Google account that signed in.
func (f *FakeGoogle) EnterpriseToken(signupName string) string {
	return "ET-" + strings.TrimPrefix(signupName, "signupUrls/")
}

// Enrol simulates a device enrolling with a token's value: the device
// appears in the enterprise's list with the facts given.
func (f *FakeGoogle) Enrol(tokenValue, serial, model, androidVersion string, secure, encrypted bool) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.enterprises {
		for name, t := range e.tokens {
			if t.value == tokenValue {
				dn := e.name + "/devices/" + randomID(8)
				d := wireDevice{Name: dn, State: "ACTIVE", EnrollmentTokenName: name,
					LastStatusReport: time.Now().UTC().Format(time.RFC3339), PolicyCompliant: true}
				d.HardwareInfo.SerialNumber, d.HardwareInfo.Model = serial, model
				d.SoftwareInfo.AndroidVersion = androidVersion
				d.ApplicationReports = append(d.ApplicationReports, struct {
					PackageName string `json:"packageName"`
					DisplayName string `json:"displayName"`
					VersionName string `json:"versionName"`
				}{"com.example.mail", "Mail", "4.2"})
				d.DeviceSettings = &struct {
					IsDeviceSecure    bool   `json:"isDeviceSecure"`
					IsEncrypted       bool   `json:"isEncrypted"`
					VerifiedBootState string `json:"verifiedBootState"`
				}{secure, encrypted, "VERIFIED"}
				e.devices[dn] = d
				// One-time: spent.
				delete(e.tokens, name)
				return dn
			}
		}
	}
	return ""
}

// Report changes what a device says, for a test that wants it to drift.
func (f *FakeGoogle) Report(deviceName string, secure, encrypted bool, androidVersion string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.enterprises {
		if d, ok := e.devices[deviceName]; ok {
			d.DeviceSettings.IsDeviceSecure, d.DeviceSettings.IsEncrypted = secure, encrypted
			d.SoftwareInfo.AndroidVersion = androidVersion
			d.LastStatusReport = time.Now().UTC().Format(time.RFC3339)
			e.devices[deviceName] = d
		}
	}
}

func (f *FakeGoogle) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/")
	f.Calls = append(f.Calls, r.Method+" "+path)
	write := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	refuse := func(status int, msg string) {
		write(status, map[string]any{"error": map[string]any{"code": status, "message": msg}})
	}
	q := r.URL.Query()

	switch {
	case r.Method == "GET" && path == "phone":
		f.mu.Unlock()
		f.phonePage(w)
		f.mu.Lock()
		return
	case r.Method == "POST" && path == "phone/enrol":
		f.mu.Unlock()
		f.phoneEnrol(w, r)
		f.mu.Lock()
		return

	case r.Method == "POST" && path == "signupUrls":
		// Google's own words, so a client that forgets the project fails
		// here the way it fails there. Found the hard way on the first real
		// bind: the fake accepted what Google refused.
		if q.Get("projectId") == "" {
			refuse(400, "Missing identifier. Provide the project id.")
			return
		}
		if q.Get("callbackUrl") == "" {
			refuse(400, "callbackUrl is required")
			return
		}
		// Google refuses to send anybody back to plain http, and says so
		// with this code. The demonstration on a laptop found that out.
		if !strings.HasPrefix(q.Get("callbackUrl"), "https://") {
			refuse(400, `domain: "androidenterprise.ApiErrors" code: "INSECURE_CALLBACK_URL"`)
			return
		}
		name := "signupUrls/" + randomID(6)
		f.signups[name] = q.Get("callbackUrl")
		write(200, map[string]any{"name": name, "url": f.public + "/fake-signin?signup=" + url.QueryEscape(name)})

	case r.Method == "GET" && path == "fake-signin":
		// Google's sign-up page, reduced to a redirect back with a token.
		name := q.Get("signup")
		cb, ok := f.signups[name]
		if !ok {
			refuse(404, "no such signup url")
			return
		}
		sep := "?"
		if strings.Contains(cb, "?") {
			sep = "&"
		}
		http.Redirect(w, r, cb+sep+"enterpriseToken="+url.QueryEscape(f.EnterpriseToken(name)), http.StatusFound)

	case r.Method == "POST" && path == "enterprises":
		if q.Get("projectId") == "" {
			refuse(400, "Missing identifier. Provide the project id.")
			return
		}
		name, token := q.Get("signupUrlName"), q.Get("enterpriseToken")
		if _, ok := f.signups[name]; !ok || token != f.EnterpriseToken(name) {
			refuse(400, "the signup url and enterprise token do not match")
			return
		}
		delete(f.signups, name)
		var in struct {
			Display string `json:"enterpriseDisplayName"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		e := &fakeEnterprise{name: "enterprises/LC" + randomID(6), display: in.Display,
			tokens: map[string]fakeToken{}, devices: map[string]wireDevice{}}
		f.enterprises[e.name] = e
		write(200, map[string]any{"name": e.name, "enterpriseDisplayName": e.display})

	case r.Method == "DELETE" && strings.HasPrefix(path, "enterprises/") && strings.Count(path, "/") == 1:
		if _, ok := f.enterprises[path]; !ok {
			refuse(404, "no such enterprise")
			return
		}
		delete(f.enterprises, path)
		write(200, map[string]any{})

	case r.Method == "PATCH" && strings.Contains(path, "/policies/"):
		ent := path[:strings.Index(path, "/policies/")]
		if _, ok := f.enterprises[ent]; !ok {
			refuse(404, "no such enterprise")
			return
		}
		var body Policy
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			refuse(400, "bad policy body")
			return
		}
		f.Policies[path] = body
		write(200, map[string]any{"name": path})

	case r.Method == "POST" && strings.HasSuffix(path, "/enrollmentTokens"):
		if f.FailTokens {
			refuse(503, "the service is unavailable")
			return
		}
		ent := strings.TrimSuffix(path, "/enrollmentTokens")
		e, ok := f.enterprises[ent]
		if !ok {
			refuse(404, "no such enterprise")
			return
		}
		var in struct {
			PolicyName         string `json:"policyName"`
			AllowPersonalUsage string `json:"allowPersonalUsage"`
			User               *struct {
				AccountIdentifier string `json:"accountIdentifier"`
			} `json:"user"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.PolicyName == "" {
			refuse(400, "policyName is required")
			return
		}
		name := ent + "/enrollmentTokens/" + randomID(6)
		t := fakeToken{value: strings.ToUpper(randomID(12)), policy: in.PolicyName, personal: in.AllowPersonalUsage}
		f.TokenUsage[name] = in.AllowPersonalUsage
		if in.User != nil {
			t.user = in.User.AccountIdentifier
		}
		e.tokens[name] = t
		exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		qr, _ := json.Marshal(map[string]any{
			"android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME": "com.google.android.apps.work.clouddpc/.receivers.CloudDeviceAdminReceiver",
			"android.app.extra.PROVISIONING_ADMIN_EXTRAS_BUNDLE": map[string]string{
				"com.google.android.apps.work.clouddpc.EXTRA_ENROLLMENT_TOKEN": t.value,
			},
		})
		write(200, map[string]any{"name": name, "value": t.value, "qrCode": string(qr), "expirationTimestamp": exp})

	case r.Method == "GET" && strings.HasSuffix(path, "/devices"):
		ent := strings.TrimSuffix(path, "/devices")
		e, ok := f.enterprises[ent]
		if !ok {
			refuse(404, "no such enterprise")
			return
		}
		out := []wireDevice{}
		for _, d := range e.devices {
			out = append(out, d)
		}
		write(200, map[string]any{"devices": out})

	case r.Method == "POST" && strings.HasSuffix(path, ":issueCommand"):
		dn := strings.TrimSuffix(path, ":issueCommand")
		if !f.hasDevice(dn) {
			refuse(404, "no such device")
			return
		}
		var in struct {
			Type   string `json:"type"`
			Params *struct {
				LostMessage struct {
					DefaultMessage string `json:"defaultMessage"`
				} `json:"lostMessage"`
				LostOrganization struct {
					DefaultMessage string `json:"defaultMessage"`
				} `json:"lostOrganization"`
				LostEmailAddress string `json:"lostEmailAddress"`
				LostPhoneNumber  struct {
					DefaultMessage string `json:"defaultMessage"`
				} `json:"lostPhoneNumber"`
			} `json:"startLostModeParams"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.Commands[dn] = append(f.Commands[dn], in.Type)
		if in.Type == "START_LOST_MODE" {
			if in.Params == nil || in.Params.LostMessage.DefaultMessage == "" {
				refuse(400, "startLostModeParams.lostMessage is required")
				return
			}
			f.LostMessages[dn] = in.Params.LostMessage.DefaultMessage + " | " + in.Params.LostOrganization.DefaultMessage +
				" | " + in.Params.LostPhoneNumber.DefaultMessage + " | " + in.Params.LostEmailAddress
		}
		write(200, map[string]any{"name": dn + "/operations/" + randomID(4), "done": true})

	case r.Method == "DELETE" && strings.Contains(path, "/devices/"):
		if !f.hasDevice(path) {
			refuse(404, "no such device")
			return
		}
		f.Wipes[path] = append([]string{}, q["wipeDataFlags"]...)
		ent := path[:strings.Index(path, "/devices/")]
		delete(f.enterprises[ent].devices, path)
		write(200, map[string]any{})

	default:
		refuse(404, "the fake does not implement "+r.Method+" "+path)
	}
}

func (f *FakeGoogle) hasDevice(name string) bool {
	for _, e := range f.enterprises {
		if _, ok := e.devices[name]; ok {
			return true
		}
	}
	return false
}

// The pretend phone: a page where a token is typed and a device enrols
// against this fake, so the demonstration's sync has something to find.
func (f *FakeGoogle) phonePage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html><meta charset=utf-8><title>A pretend Android phone</title>
<body style="font-family:system-ui;max-width:520px;margin:48px auto;padding:0 16px">
<h1 style="font-size:20px">A pretend Android phone</h1>
<p>This stands in for a phone's first-run screen. Paste the enrolment token the
console made, and the phone enrols against the fake Google. Then press
<b>Sync now</b> on the console's Android page.</p>
<form method=post action=/phone/enrol>
<label>Token<br><input name=token required style="width:100%;padding:8px;font:inherit"></label><br><br>
<label>Serial<br><input name=serial value="PHONE-0001" style="width:100%;padding:8px;font:inherit"></label><br><br>
<label><input type=checkbox name=secure checked> A screen lock is set</label><br>
<label><input type=checkbox name=encrypted checked> Storage is encrypted</label><br>
<label>Android version <input name=version value="15" style="padding:6px;font:inherit;width:60px"></label><br><br>
<button style="padding:8px 14px;font:inherit">Enrol</button></form>`))
}

func (f *FakeGoogle) phoneEnrol(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	name := f.Enrol(strings.TrimSpace(r.FormValue("token")), r.FormValue("serial"), "Pixel 8a",
		r.FormValue("version"), r.FormValue("secure") != "", r.FormValue("encrypted") != "")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if name == "" {
		_, _ = w.Write([]byte(`<p style="font-family:system-ui">That token is not one the fake Google issued, or it was already used. <a href=/phone>Back</a></p>`))
		return
	}
	_, _ = w.Write([]byte(`<p style="font-family:system-ui">Enrolled as <code>` + name +
		`</code>. Now press Sync now on the console's Android page. <a href=/phone>Back</a></p>`))
}
