// Package agent is the half of this platform that runs on the managed
// machine.
//
// What it does: generates a key, enrols with a one-time token, holds an
// identity certificate, reports what it can see about the machine, fetches
// the instructions addressed to it, carries them out, and says it has.
//
// THE KEY NEVER LEAVES THE DEVICE. It is generated here, written with owner-
// only permissions, and only a certificate signing request is ever
// transmitted. There is no code path in this package that serialises the
// private key to a network connection, and the enrolment response carries a
// certificate rather than a key because the server never has one to give.
//
// THE AGENT REPORTS FACTS; THE SERVER JUDGES. No policy is evaluated here and
// no policy is stored here. A device that has been tampered with cannot be
// made compliant by editing a local rule file, because there is no local rule
// file. What it CAN do is lie about what it sees, and that is inherent to
// agent-based compliance rather than a defect of this design: the answer is
// hardware attestation, which is listed as not built.
//
// ANYTHING IT CANNOT DETERMINE IS LEFT UNSAID. The report's fields are
// pointers and a probe that cannot read a setting returns nil rather than
// guessing false. The server already treats silence as state_unknown and
// never as a pass, so an agent running on a platform it only half supports
// produces an honest "we do not know" rather than a fleet of green rows.
package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"platform/internal/command"
	"strings"
	"time"

	"github.com/google/uuid"

	"platform/internal/policy"
)

var (
	ErrAlreadyEnrolled = errors.New("agent: this device is already enrolled")
	ErrNotEnrolled     = errors.New("agent: this device is not enrolled yet")
	ErrRefused         = errors.New("agent: the server refused")
)

// Probe reads the machine. Everything it cannot determine is left nil, which
// the server reads as "did not say" rather than as a pass.
type Probe interface {
	Name() string
	Serial() (string, error)
	OSFamily() string
	Hostname() string
	Collect(ctx context.Context) (policy.Report, error)
}

// Enforcer carries out an instruction locally.
//
// It is the agent's equivalent of the server's PushProvider: the one place
// the operating system lands. Locking a Mac, clearing a passcode and wiping
// a volume are privileged platform calls, so the implementations are per
// platform and the port keeps the lifecycle below free of them.
type Enforcer interface {
	Name() string
	Do(ctx context.Context, kind string) error
}

// Remediator is an Enforcer that can also put a failed requirement right:
// turn the firewall on, start disk encryption, set the password length
// policy, shorten the screen lock. It is a separate, optional interface so
// an enforcer built only for instructions (lock, wipe) does not have to
// pretend. Asked only for findings the policy marked Fix, and never for
// one the probe could not read.
type Remediator interface {
	Enforcer
	Remediate(ctx context.Context, f policy.Finding) error
}

// ErrDeferred is what a remediator returns when it has set the change in
// motion but the machine will finish it later: FileVault enables at the
// next login, BitLocker encrypts in the background. Not a failure, and not
// counted as done either, so the report is not taken again on its account.
var ErrDeferred = errors.New("agent: set in motion; the machine will finish it later")

type Config struct {
	// ServerURL is the tenant's own hostname, which is also what decides
	// the tenant. The agent never sends a tenant identifier: it would be a
	// claim rather than a fact, and the server would be wrong to read it.
	ServerURL string
	Dir       string
	Probe     Probe
	Enforcer  Enforcer
	Log       *slog.Logger
	// Wrap sits around the transport this agent builds, rather than
	// replacing it. That distinction matters: a replaced transport would
	// not present the device certificate, so a test using one would prove
	// the lifecycle works and prove nothing about the identity it is
	// supposed to carry. Deployments behind a proxy use it too.
	Wrap func(http.RoundTripper) http.RoundTripper
	// RootCAs lets a test, or a deployment with a private certificate
	// authority in front of the gateway, say who to trust for the SERVER's
	// certificate. Nil means the host's own trust store.
	RootCAs *x509.CertPool
	// RecoveryKeyFile is where a platform helper leaves the disk-encryption
	// recovery key for escrow (F11). The agent reads it, hands it up
	// sealed, and removes it. Empty means no escrow on this machine.
	RecoveryKeyFile string
}

type Agent struct {
	// The tenant's command signing keys, fetched on first need.
	tenant uuid.UUID
	keys   []*rsa.PublicKey
	cfg    Config
	log    *slog.Logger
	client *http.Client
	state  state
	// fixed is how many findings the last report's remediation changed,
	// so the cycle knows to report again and show the result.
	fixed int
}

type state struct {
	DeviceID uuid.UUID `json:"device_id"`
	Server   string    `json:"server"`
	NotAfter time.Time `json:"certificate_not_after"`
}

func New(cfg Config) (*Agent, error) {
	if cfg.ServerURL == "" {
		return nil, errors.New("agent: no server address")
	}
	if cfg.Dir == "" {
		return nil, errors.New("agent: no state directory")
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Probe == nil {
		return nil, errors.New("agent: no probe")
	}
	if cfg.Enforcer == nil {
		cfg.Enforcer = NotConfigured{}
	}
	cfg.ServerURL = strings.TrimRight(cfg.ServerURL, "/")

	a := &Agent{cfg: cfg, log: cfg.Log}
	// Owner only. The directory holds the private key, so a world-readable
	// one is the same as publishing it.
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	_ = a.loadState()
	return a, nil
}

// ---------------------------------------------------------------- the files

func (a *Agent) path(name string) string { return filepath.Join(a.cfg.Dir, name) }

func (a *Agent) loadState() error {
	b, err := os.ReadFile(a.path("device.json"))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &a.state)
}

func (a *Agent) saveState() error {
	b, err := json.MarshalIndent(a.state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(a.path("device.json"), b, 0o600)
}

// Enrolled reports whether this machine already holds an identity.
func (a *Agent) Enrolled() bool {
	if a.state.DeviceID == uuid.Nil {
		return false
	}
	_, err := os.Stat(a.path("cert.pem"))
	return err == nil
}

func (a *Agent) DeviceID() uuid.UUID { return a.state.DeviceID }

// ---------------------------------------------------------------- enrolling

// Enrol exchanges a one-time token for an identity certificate.
//
// The order matters and is the reason the key is written last: a key on disk
// with no certificate is a device that looks half enrolled and will not
// retry cleanly. Everything is held in memory until the server has answered,
// and only then is any of it stored.
func (a *Agent) Enrol(ctx context.Context, token string) error {
	if a.Enrolled() {
		return ErrAlreadyEnrolled
	}
	if strings.TrimSpace(token) == "" {
		return errors.New("agent: no enrolment token")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	// The subject here is a courtesy, not a claim. The authority discards
	// it and writes the device's real identity from what it knows, so what
	// goes in is only ever useful for reading a packet capture.
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: a.cfg.Probe.Hostname()}}, key)
	if err != nil {
		return err
	}
	serial, err := a.cfg.Probe.Serial()
	if err != nil {
		return fmt.Errorf("agent: could not read this machine's serial number: %w", err)
	}

	body, err := json.Marshal(map[string]string{
		"token":  token,
		"csr":    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		"serial": serial,
		"name":   a.cfg.Probe.Hostname(),
	})
	if err != nil {
		return err
	}

	// Plain client: enrolment is the one call made before a certificate
	// exists, so it cannot present one.
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: a.wrap(&http.Transport{TLSClientConfig: &tls.Config{RootCAs: a.cfg.RootCAs}}),
	}
	req, err := http.NewRequestWithContext(ctx, "POST",
		a.cfg.ServerURL+"/api/enrol", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("%w: %s", ErrRefused, serverSays(raw, resp.StatusCode))
	}

	var out struct {
		DeviceID    uuid.UUID `json:"device_id"`
		Certificate string    `json:"certificate"`
		Authority   string    `json:"authority"`
		NotAfter    time.Time `json:"not_after"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("agent: the enrolment answer could not be read: %w", err)
	}
	if out.DeviceID == uuid.Nil || out.Certificate == "" {
		return errors.New("agent: the enrolment answer carried no identity")
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// 0600: the key is the whole of this device's identity. Anything wider
	// and any local account can become this machine.
	if err := os.WriteFile(a.path("key.pem"), keyPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(a.path("cert.pem"), []byte(out.Certificate), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(a.path("ca.pem"), []byte(out.Authority), 0o644); err != nil {
		return err
	}
	a.state = state{DeviceID: out.DeviceID, Server: a.cfg.ServerURL, NotAfter: out.NotAfter}
	if err := a.saveState(); err != nil {
		return err
	}
	a.client = nil // rebuilt on next use, now with a certificate to present

	a.log.Info("enrolled", "device", out.DeviceID, "until", out.NotAfter.Format(time.RFC3339))
	return nil
}

// ------------------------------------------------------------- the client

// identified builds the client that presents this device's certificate.
//
// Every call after enrolment goes through it, which is what makes the
// device's identity a property of the connection rather than something
// carried in a header that could be copied out of a log.
func (a *Agent) identified() (*http.Client, error) {
	if a.client != nil {
		return a.client, nil
	}
	if !a.Enrolled() {
		return nil, ErrNotEnrolled
	}
	cert, err := tls.LoadX509KeyPair(a.path("cert.pem"), a.path("key.pem"))
	if err != nil {
		return nil, fmt.Errorf("agent: could not load this device's identity: %w", err)
	}
	a.client = &http.Client{
		Timeout: 30 * time.Second,
		Transport: a.wrap(&http.Transport{TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      a.cfg.RootCAs,
		}}),
	}
	return a.client, nil
}

func (a *Agent) wrap(rt http.RoundTripper) http.RoundTripper {
	if a.cfg.Wrap == nil {
		return rt
	}
	return a.cfg.Wrap(rt)
}

func (a *Agent) call(ctx context.Context, method, path string, body any) ([]byte, int, error) {
	client, err := a.identified()
	if err != nil {
		return nil, 0, err
	}
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.cfg.ServerURL+path, r)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return raw, resp.StatusCode, nil
}

// serverSays pulls the server's own words out of an error body, so a failure
// on a device reads as the reason rather than as a status code.
func serverSays(raw []byte, status int) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &e) == nil && e.Error != "" {
		return e.Error
	}
	return fmt.Sprintf("HTTP %d", status)
}

// ---------------------------------------------------------------- reporting

type Verdict struct {
	State    string           `json:"state"`
	Findings []policy.Finding `json:"findings"`
	Policies []string         `json:"policies"`
	// DeviceState is what the server now holds this machine to be, which
	// is the verdict unless a person or a policy has quarantined it.
	DeviceState string `json:"device_state"`
	// Enforcement says what the server did on this report beyond judging.
	Enforcement string `json:"enforcement"`
}

// QuarantineKind is what the enforcer is asked to do when the server says
// this machine is quarantined: F9's "network-access revocation", done where
// it can be done, which is on the machine. The bundled enforcers do nothing
// with it; an operator's ScriptEnforcer can drop the VPN or the corporate
// Wi-Fi profile. The vendor channels will carry the same thing once the
// Apple seam closes.
const QuarantineKind = "quarantine"

// Report sends what this machine can see and brings back the verdict.
//
// The verdict comes back so an agent can show the person holding the laptop
// what to fix, without them needing a console account they may not have.
func (a *Agent) Report(ctx context.Context) (Verdict, error) {
	if !a.Enrolled() {
		return Verdict{}, ErrNotEnrolled
	}
	rep, err := a.cfg.Probe.Collect(ctx)
	if err != nil {
		return Verdict{}, err
	}
	raw, status, err := a.call(ctx, "POST",
		"/api/devices/"+a.state.DeviceID.String()+"/report", rep)
	if err != nil {
		return Verdict{}, err
	}
	if status != http.StatusOK {
		return Verdict{}, fmt.Errorf("%w: %s", ErrRefused, serverSays(raw, status))
	}
	var v Verdict
	if err := json.Unmarshal(raw, &v); err != nil {
		return Verdict{}, err
	}
	a.log.Info("reported", "state", v.State, "findings", len(v.Findings),
		"device_state", v.DeviceState)
	if v.DeviceState == "quarantined" {
		// Told every report, not only the first: an enforcer that acts
		// once and is undone by a reboot needs reminding, and one that is
		// idempotent does not mind.
		if err := a.cfg.Enforcer.Do(ctx, QuarantineKind); err != nil {
			a.log.Warn("this machine is quarantined and the enforcer cannot act on it",
				"enforcer", a.cfg.Enforcer.Name(), "err", err)
		}
	}
	a.fixed = a.remediate(ctx, v)
	return v, nil
}

// remediate asks the enforcer to put right what the verdict says this
// machine may put right. The server judged and marked; the device acts
// only on the marks. Two things are never acted on: a finding the policy
// did not mark, because a tenant that only wants to observe must not find
// its settings changed, and a finding that could not be read, because a
// setting the agent cannot see is not one it should change. Returns how
// many settings changed, so the cycle can report again and show it.
func (a *Agent) remediate(ctx context.Context, v Verdict) int {
	rem, can := a.cfg.Enforcer.(Remediator)
	fixed := 0
	for _, f := range v.Findings {
		if !f.Fix || f.Unknown {
			continue
		}
		if !can {
			a.log.Warn("the policy asks this machine to put a finding right and the enforcer cannot",
				"rule", f.Rule, "enforcer", a.cfg.Enforcer.Name())
			continue
		}
		err := rem.Remediate(ctx, f)
		switch {
		case errors.Is(err, ErrDeferred):
			a.log.Info("set in motion", "rule", f.Rule, "note", err)
		case err != nil:
			a.log.Error("could not put right", "rule", f.Rule, "err", err)
		default:
			a.log.Info("put right", "rule", f.Rule)
			fixed++
		}
	}
	return fixed
}

// ---------------------------------------------------------------- commands

type instruction struct {
	ID       uuid.UUID `json:"id"`
	DeviceID uuid.UUID `json:"device_id"`
	Type     string    `json:"type"`
	Label    string    `json:"label"`
	Reason   string    `json:"reason"`
	Code     string    `json:"code"`
	// What the signature covers, and the signature. Verified against the
	// tenant's published keys before anything is carried out.
	Nonce          string     `json:"nonce"`
	NonceExpiresAt *time.Time `json:"nonce_expires_at"`
	Signature      string     `json:"signature"`
}

// fetchKeys reads the tenant's command signing keys, current first. They
// are kept in memory for the life of the process and fetched again when a
// signature fits none of them, which is what a rotation looks like from
// here.
func (a *Agent) fetchKeys(ctx context.Context) error {
	raw, status, err := a.call(ctx, "GET", "/api/my/signing-keys", nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("%w: %s", ErrRefused, serverSays(raw, status))
	}
	var out struct {
		TenantID uuid.UUID `json:"tenant_id"`
		Keys     []struct {
			Version int    `json:"version"`
			PEM     string `json:"public_key_pem"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return err
	}
	var keys []*rsa.PublicKey
	for _, k := range out.Keys {
		block, _ := pem.Decode([]byte(k.PEM))
		if block == nil {
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			continue
		}
		if r, ok := pub.(*rsa.PublicKey); ok {
			keys = append(keys, r)
		}
	}
	if len(keys) == 0 {
		return errors.New("agent: the server published no signing key")
	}
	a.tenant, a.keys = out.TenantID, keys
	return nil
}

// verify says whether an instruction's signature fits one of the keys
// held. It rebuilds the signed payload with the same code the server used.
func (a *Agent) verify(c instruction) bool {
	if c.Signature == "" || a.tenant == uuid.Nil {
		return false
	}
	cmd := command.Command{ID: c.ID, DeviceID: c.DeviceID, Type: command.Type(c.Type),
		Nonce: c.Nonce, NonceExpiresAt: c.NonceExpiresAt, Signature: c.Signature}
	for _, k := range a.keys {
		if command.Verify(k, a.tenant, cmd) == nil {
			return true
		}
	}
	return false
}

// verified is verify with one refetch of the keys, for a rotation.
func (a *Agent) verified(ctx context.Context, c instruction) bool {
	if len(a.keys) == 0 || !a.verify(c) {
		if err := a.fetchKeys(ctx); err != nil {
			a.log.Error("could not fetch the signing keys", "err", err)
			return false
		}
	}
	return a.verify(c)
}

// Sync fetches this device's outstanding instructions, carries them out, and
// acknowledges the ones that ran.
//
// A push notification is a WAKE-UP, not a delivery. Apple's service carries
// no payload worth acting on, and neither do Google's or Microsoft's: the
// instruction travels over this connection, authenticated by this device's
// own certificate. That is why the loop below closes today and why the push
// provider, when it arrives, will only make it timely rather than possible.
//
// An instruction that fails locally is NOT acknowledged. Acknowledgement is
// the only state the console reports as done, so a lock that did not happen
// must leave the command outstanding rather than silently complete.
func (a *Agent) Sync(ctx context.Context) (done int, err error) {
	return a.sync(ctx, 0)
}

// Listen is Sync that waits: the server holds the request until there is
// work or the wait runs out, so a lock lands in seconds (F12). Run keeps
// one of these open at all times while enrolled.
func (a *Agent) Listen(ctx context.Context, wait time.Duration) (int, error) {
	return a.sync(ctx, wait)
}

func (a *Agent) sync(ctx context.Context, wait time.Duration) (done int, err error) {
	if !a.Enrolled() {
		return 0, ErrNotEnrolled
	}
	path := "/api/my/commands"
	if wait > 0 {
		path += fmt.Sprintf("?wait=%d", int(wait.Seconds()))
	}
	raw, status, err := a.call(ctx, "GET", path, nil)
	if err != nil {
		return 0, err
	}
	if status != http.StatusOK {
		return 0, fmt.Errorf("%w: %s", ErrRefused, serverSays(raw, status))
	}
	var out struct {
		Commands []instruction `json:"commands"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return 0, err
	}

	for _, c := range out.Commands {
		if c.Code == "" {
			// Not yet deliverable: it has been asked for but not approved,
			// or its code has expired. Leave it alone.
			continue
		}
		// Nothing is carried out on the strength of the connection alone:
		// the instruction has to carry the tenant's signature, verified
		// here with the same code the server signed with. One that does
		// not fit is refused and left outstanding, so the console shows
		// it was never done rather than quietly done by something else.
		if !a.verified(ctx, c) {
			a.log.Error("refusing an instruction whose signature does not verify", "command", c.ID, "type", c.Type)
			continue
		}
		a.log.Info("carrying out", "command", c.ID, "type", c.Type, "reason", c.Reason)
		if derr := a.cfg.Enforcer.Do(ctx, c.Type); derr != nil {
			// Reported, not acknowledged, and not fatal to the run: one
			// instruction this agent cannot carry out must not stop it
			// reporting or taking the next one.
			a.log.Error("could not carry out", "command", c.ID, "type", c.Type, "err", derr)
			continue
		}
		ackRaw, ackStatus, aerr := a.call(ctx, "POST",
			"/api/commands/"+c.ID.String()+"/ack?code="+c.Code, nil)
		if aerr != nil {
			return done, aerr
		}
		if ackStatus != http.StatusOK {
			a.log.Error("acknowledgement refused", "command", c.ID,
				"reason", serverSays(ackRaw, ackStatus))
			continue
		}
		done++
	}
	return done, nil
}

// RenewalLead is how early the agent starts trying.
//
// Shorter than the server's window on purpose. The server allows renewal in
// the last thirty days; the agent starts at twenty-five, so a device that
// checks in weekly has four attempts before anything is urgent and a
// temporary failure is not the last chance. Starting at the full thirty
// would mean a device whose clock is a day fast is refused on its first try
// every year.
const RenewalLead = 25 * 24 * time.Hour

// Renew asks for a fresh certificate using the one this device holds.
//
// It writes the new certificate only after the server has answered, and
// keeps the old one until that write succeeds, so a failure anywhere leaves
// the device with a working identity rather than half a new one.
func (a *Agent) Renew(ctx context.Context) error {
	if !a.Enrolled() {
		return ErrNotEnrolled
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: a.cfg.Probe.Hostname()}}, key)
	if err != nil {
		return err
	}

	raw, status, err := a.call(ctx, "POST", "/api/my/certificate", map[string]string{
		"csr": string(pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
	})
	if err != nil {
		return err
	}
	if status == http.StatusConflict {
		// Not due yet. Not an error: the agent asked early, which is what
		// a clock that is slightly fast produces, and it will ask again.
		return nil
	}
	if status != http.StatusCreated {
		return fmt.Errorf("%w: %s", ErrRefused, serverSays(raw, status))
	}

	var out struct {
		Certificate string    `json:"certificate"`
		Authority   string    `json:"authority"`
		NotAfter    time.Time `json:"not_after"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return err
	}
	if out.Certificate == "" {
		return errors.New("agent: the renewal answer carried no certificate")
	}

	// The new key and certificate are written together, and only now. Up to
	// this point a failure leaves the old pair untouched and working.
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(a.path("key.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(a.path("cert.pem"), []byte(out.Certificate), 0o644); err != nil {
		return err
	}
	if out.Authority != "" {
		_ = os.WriteFile(a.path("ca.pem"), []byte(out.Authority), 0o644)
	}
	a.state.NotAfter = out.NotAfter
	if err := a.saveState(); err != nil {
		return err
	}
	// The next call has to present the new certificate, not the old one.
	a.client = nil

	a.log.Info("certificate renewed", "until", out.NotAfter.Format(time.RFC3339))
	return nil
}

// dueForRenewal reads the expiry from the certificate on disk rather than
// from the state file, because the certificate is the thing the server will
// judge and a state file can drift from it.
func (a *Agent) dueForRenewal(now time.Time) bool {
	b, err := os.ReadFile(a.path("cert.pem"))
	if err != nil {
		return false
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	return cert.NotAfter.Sub(now) <= RenewalLead
}

// RunOnce is one cycle: renew if the identity is running out, then say what
// we see, then do what we are told.
//
// Renewal goes first because the other two need an identity the server will
// accept, and a device that has let its certificate expire can do neither.
func (a *Agent) RunOnce(ctx context.Context) error {
	if a.dueForRenewal(time.Now().UTC()) {
		if err := a.Renew(ctx); err != nil {
			// Not fatal to the cycle. There is still time left on the old
			// certificate, so reporting and obeying should carry on.
			a.log.Error("could not renew the certificate", "err", err)
		}
	}
	if _, err := a.Report(ctx); err != nil {
		return err
	}
	if a.fixed > 0 {
		// Something was put right. Say so now rather than at the next
		// cycle, so the console shows the fix within the minute it
		// happened. Once: a fix that did not take is not retried in a
		// loop here, the next cycle will find it again.
		if _, err := a.Report(ctx); err != nil {
			return err
		}
	}
	if err := a.Escrow(ctx); err != nil {
		a.log.Error("could not escrow the recovery key", "err", err)
	}
	_, err := a.Sync(ctx)
	return err
}

// Escrow hands up the recovery key a helper left for it, once: the file
// is removed when the server has it. Nothing happens when there is no
// file, which is the usual case.
func (a *Agent) Escrow(ctx context.Context) error {
	if a.cfg.RecoveryKeyFile == "" || !a.Enrolled() {
		return nil
	}
	raw, err := os.ReadFile(a.cfg.RecoveryKeyFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	key := recoveryKeyIn(string(raw))
	if key == "" {
		return nil
	}
	kind := "other"
	switch a.cfg.Probe.OSFamily() {
	case "macos":
		kind = "filevault"
	case "windows":
		kind = "bitlocker"
	}
	resp, status, err := a.call(ctx, "POST", "/api/my/recovery-key", map[string]string{"kind": kind, "key": key})
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("%w: %s", ErrRefused, serverSays(resp, status))
	}
	a.log.Info("recovery key escrowed", "kind", kind)
	return os.Remove(a.cfg.RecoveryKeyFile)
}

// recoveryKeyIn reads the key out of what a helper left: the bare key, or
// the plist that fdesetup writes when a deferred FileVault enablement
// completes at login (the agent's own native remediation points fdesetup
// at the escrow file). A plist with no RecoveryKey yet is "nothing to
// escrow" rather than an escrow of the plist text.
func recoveryKeyIn(content string) string {
	s := strings.TrimSpace(content)
	if !strings.Contains(s, "<plist") {
		return s
	}
	v := after(s, "<key>RecoveryKey</key>", "</string>")
	v = strings.TrimSpace(strings.TrimPrefix(v, "<string>"))
	return v
}

// Run loops until the context ends.
//
// The backoff is deliberate and it doubles: a fleet of ten thousand agents
// retrying every thirty seconds against a gateway that has just come back up
// is a second outage caused by the first.
func (a *Agent) Run(ctx context.Context, every time.Duration) error {
	if every <= 0 {
		every = 15 * time.Minute
	}
	// The listener: one held request at a time, re-opened as soon as it
	// returns, backing off on failure like the cycle does. It is what
	// turns "at the next check-in" into "now".
	go a.listen(ctx)
	backoff := time.Duration(0)
	for {
		if err := a.RunOnce(ctx); err != nil {
			if backoff == 0 {
				backoff = 30 * time.Second
			} else if backoff < 30*time.Minute {
				backoff *= 2
			}
			a.log.Error("cycle failed", "err", err, "retrying_in", backoff)
		} else {
			backoff = 0
		}

		wait := every
		if backoff > 0 {
			wait = backoff
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// ListenWait is how long one held request lasts: under the agent's own
// client timeout, under the gateway's cap, and under the timeout any
// balancer in between is likely to have.
const ListenWait = 25 * time.Second

func (a *Agent) listen(ctx context.Context) {
	backoff := time.Duration(0)
	for {
		if ctx.Err() != nil {
			return
		}
		if !a.Enrolled() {
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
			}
			continue
		}
		if _, err := a.Listen(ctx, ListenWait); err != nil {
			if backoff == 0 {
				backoff = 5 * time.Second
			} else if backoff < 5*time.Minute {
				backoff *= 2
			}
			a.log.Warn("listening failed", "err", err, "retrying_in", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			continue
		}
		backoff = 0
	}
}
