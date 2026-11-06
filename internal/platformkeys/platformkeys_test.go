package platformkeys

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	claim   = "claim-signing-key-of-thirty-two-bytes!"
	session = "session-signing-key-thirty-two-bytes"
	sealing = "sealing-key-exactly-32-bytes-ok!"
	prevKey = "previous-master-exactly-32-bytes"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func good() map[string]string {
	return map[string]string{
		"MDM_CLAIM_SIGNING_KEY":   claim,
		"MDM_SESSION_SIGNING_KEY": session,
		"MDM_SEALING_KEY":         sealing,
	}
}

// ---------------------------------------------------------------- env

func TestKeysComeFromTheEnvironmentByDefault(t *testing.T) {
	src, err := Choose(env(good()))
	if err != nil {
		t.Fatalf("choose: %v", err)
	}
	k, err := Load(context.Background(), src)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(k.Claim) != claim || string(k.Session) != session || string(k.Sealing) != sealing || k.SealingPrevious != nil {
		t.Fatalf("got %+v", k)
	}
	if !strings.Contains(k.From, "environment") {
		t.Fatalf("from %q", k.From)
	}
}

func TestAMissingKeyIsNamedWithWhereToSetIt(t *testing.T) {
	m := good()
	delete(m, "MDM_SESSION_SIGNING_KEY")
	_, err := Load(context.Background(), Env{Getenv: env(m)})
	if err == nil || !strings.Contains(err.Error(), "session_signing_key is not set") ||
		!strings.Contains(err.Error(), "MDM_SESSION_SIGNING_KEY") {
		t.Fatalf("got %v", err)
	}
}

func TestLengthsAreChecked(t *testing.T) {
	m := good()
	m["MDM_SEALING_KEY"] = "thirty-one-bytes-is-not-enough!"
	if _, err := Load(context.Background(), Env{Getenv: env(m)}); err == nil ||
		!strings.Contains(err.Error(), "exactly 32 bytes, got 31") {
		t.Fatalf("a 31-byte sealing key: %v", err)
	}
	m = good()
	m["MDM_CLAIM_SIGNING_KEY"] = "short"
	if _, err := Load(context.Background(), Env{Getenv: env(m)}); err == nil ||
		!strings.Contains(err.Error(), "at least 32 bytes, got 5") {
		t.Fatalf("a short claim key: %v", err)
	}
	m = good()
	m["MDM_SEALING_KEY_PREVIOUS"] = "short"
	if _, err := Load(context.Background(), Env{Getenv: env(m)}); err == nil ||
		!strings.Contains(err.Error(), "sealing_key_previous must be exactly 32") {
		t.Fatalf("a short previous master: %v", err)
	}
}

// One key doing three jobs is one compromise doing three.
func TestTheThreeKeysMustDiffer(t *testing.T) {
	m := good()
	m["MDM_SESSION_SIGNING_KEY"] = claim
	if _, err := Load(context.Background(), Env{Getenv: env(m)}); err == nil ||
		!strings.Contains(err.Error(), "three different keys") {
		t.Fatalf("got %v", err)
	}
	m = good()
	m["MDM_SEALING_KEY_PREVIOUS"] = sealing
	if _, err := Load(context.Background(), Env{Getenv: env(m)}); err == nil ||
		!strings.Contains(err.Error(), "same key") {
		t.Fatalf("previous equal to current: %v", err)
	}
}

func TestThePreviousMasterIsReadWhenSet(t *testing.T) {
	m := good()
	m["MDM_SEALING_KEY_PREVIOUS"] = prevKey
	k, err := Load(context.Background(), Env{Getenv: env(m)})
	if err != nil || string(k.SealingPrevious) != prevKey {
		t.Fatalf("%+v %v", k, err)
	}
	cur, prev, err := LoadSealing(context.Background(), Env{Getenv: env(m)})
	if err != nil || string(cur) != sealing || string(prev) != prevKey {
		t.Fatalf("sealing pair: %q %q %v", cur, prev, err)
	}
	// And tenantctl's read needs the sealing keys alone, not the signers.
	only := map[string]string{"MDM_SEALING_KEY": sealing}
	if cur, prev, err := LoadSealing(context.Background(), Env{Getenv: env(only)}); err != nil || string(cur) != sealing || prev != nil {
		t.Fatalf("sealing alone: %q %q %v", cur, prev, err)
	}
}

func TestBase64ValuesAreDecoded(t *testing.T) {
	m := good()
	m["MDM_SEALING_KEY"] = "base64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	k, err := Load(context.Background(), Env{Getenv: env(m)})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(k.Sealing) != 32 || k.Sealing[0] != 0 || k.Sealing[31] != 31 {
		t.Fatalf("decoded to %v", k.Sealing)
	}
	m["MDM_SEALING_KEY"] = "base64:not base64!"
	if _, err := Load(context.Background(), Env{Getenv: env(m)}); err == nil || !strings.Contains(err.Error(), "does not decode") {
		t.Fatalf("bad base64: %v", err)
	}
}

// The control --break-keydescribe prints the bytes. This is the test that
// notices.
func TestTheStartUpLineNeverHoldsAKey(t *testing.T) {
	m := good()
	m["MDM_SEALING_KEY_PREVIOUS"] = prevKey
	k, err := Load(context.Background(), Env{Getenv: env(m)})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	line := k.Describe()
	for _, secret := range []string{claim, session, sealing, prevKey} {
		if strings.Contains(line, secret) || strings.Contains(line, secret[:12]) {
			t.Fatalf("the start-up line holds a key: %s", line)
		}
	}
	if !strings.Contains(line, "claim 38 bytes") || !strings.Contains(line, "sealing 32 bytes") ||
		!strings.Contains(line, "previous master 32 bytes") || !strings.Contains(line, "fingerprint") {
		t.Fatalf("line: %s", line)
	}
	// Two different keys, two different fingerprints.
	if describe("x", []byte(claim)) == describe("x", []byte(session)) {
		t.Fatal("fingerprints do not tell keys apart")
	}
}

// ---------------------------------------------------------------- files

func keyDir(t *testing.T, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	for name, v := range map[string]string{ClaimName: claim, SessionName: session, SealingName: sealing} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(v+"\n"), mode); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestKeysComeFromOwnerOnlyFiles(t *testing.T) {
	dir := keyDir(t, 0o400)
	src, err := Choose(env(map[string]string{"MDM_KEY_SOURCE": "files", "MDM_KEY_DIR": dir}))
	if err != nil {
		t.Fatalf("choose: %v", err)
	}
	k, err := Load(context.Background(), src)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// The editor's trailing newline is not part of the key.
	if string(k.Claim) != claim || string(k.Sealing) != sealing || k.SealingPrevious != nil {
		t.Fatalf("got %q %q", k.Claim, k.Sealing)
	}
	if !strings.Contains(k.From, dir) {
		t.Fatalf("from %q", k.From)
	}
	// A missing required key names the file to write.
	os.Remove(filepath.Join(dir, SessionName))
	_, err = Load(context.Background(), src)
	if err == nil || !strings.Contains(err.Error(), filepath.Join(dir, SessionName)) {
		t.Fatalf("missing file: %v", err)
	}
}

// The control --break-keyfilemode reads a file anyone can read. This is
// the test that notices.
func TestAKeyFileOtherUsersCanReadIsRefused(t *testing.T) {
	dir := keyDir(t, 0o644)
	_, err := Load(context.Background(), Files{Dir: dir})
	if err == nil || !strings.Contains(err.Error(), "readable by other users") || !strings.Contains(err.Error(), "0400") {
		t.Fatalf("got %v", err)
	}
}

func TestAnUnknownSourceIsRefusedRatherThanFallingBack(t *testing.T) {
	m := good()
	m["MDM_KEY_SOURCE"] = "aws"
	if _, err := Choose(env(m)); err == nil || !strings.Contains(err.Error(), `"aws" is not a source`) {
		t.Fatalf("got %v", err)
	}
}

// ---------------------------------------------------------------- vault

// A KV v2 server: one secret at the configured path, one token it
// accepts, one AppRole it logs in.
type fakeVault struct {
	token     string
	namespace string
	fields    map[string]string
	roleID    string
	secretID  string
	reads     int
	refuse    bool
	sawNS     string
	sawMethod string
}

func (f *fakeVault) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in["role_id"] != f.roleID || in["secret_id"] != f.secretID {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"invalid role or secret ID"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": f.token}})
	})
	mux.HandleFunc("/v1/secret/data/mdm/platform", func(w http.ResponseWriter, r *http.Request) {
		f.reads++
		f.sawNS = r.Header.Get("X-Vault-Namespace")
		f.sawMethod = r.Method
		if r.Header.Get("X-Vault-Token") != f.token || f.refuse {
			w.WriteHeader(403)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"data": f.fields, "metadata": map[string]any{"version": 3},
		}})
	})
	return mux
}

func vaultFields() map[string]string {
	return map[string]string{ClaimName: claim, SessionName: session, SealingName: sealing, SealingPreviousName: prevKey}
}

func caFile(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	var cert *x509.Certificate = srv.Certificate()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func credFile(t *testing.T, name, value string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(value+"\n"), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAVaultIsReadWithATokenOverTLS(t *testing.T) {
	f := &fakeVault{token: "hvs.test-token", fields: vaultFields()}
	srv := httptest.NewTLSServer(f.handler())
	defer srv.Close()

	src, err := Choose(env(map[string]string{
		"MDM_KEY_SOURCE":       "vault",
		"MDM_VAULT_ADDR":       srv.URL,
		"MDM_VAULT_PATH":       "secret/data/mdm/platform",
		"MDM_VAULT_NAMESPACE":  "mdm",
		"MDM_VAULT_TOKEN_FILE": credFile(t, "token", "hvs.test-token", 0o600),
		"MDM_VAULT_CA_FILE":    caFile(t, srv),
	}))
	if err != nil {
		t.Fatalf("choose: %v", err)
	}
	k, err := Load(context.Background(), src)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(k.Claim) != claim || string(k.Session) != session || string(k.Sealing) != sealing || string(k.SealingPrevious) != prevKey {
		t.Fatalf("got %+v", k)
	}
	if f.reads != 1 {
		t.Fatalf("the secret was read %d times; the four keys come from one read", f.reads)
	}
	if f.sawNS != "mdm" || f.sawMethod != http.MethodGet {
		t.Fatalf("namespace %q method %q", f.sawNS, f.sawMethod)
	}
	if !strings.Contains(k.From, srv.URL) || !strings.Contains(k.From, "secret/data/mdm/platform") {
		t.Fatalf("from %q", k.From)
	}
}

func TestAnAppRoleLogsInFirst(t *testing.T) {
	f := &fakeVault{token: "hvs.from-login", fields: vaultFields(), roleID: "role-1", secretID: "secret-1"}
	srv := httptest.NewTLSServer(f.handler())
	defer srv.Close()
	v := &Vault{
		Addr: srv.URL, Path: "secret/data/mdm/platform",
		RoleID: "role-1", SecretIDFile: credFile(t, "secret-id", "secret-1", 0o600),
		CAFile: caFile(t, srv),
	}
	k, err := Load(context.Background(), v)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(k.Sealing) != sealing {
		t.Fatalf("got %+v", k)
	}
	// A wrong secret id is the vault's refusal, in its words.
	v2 := &Vault{
		Addr: srv.URL, Path: "secret/data/mdm/platform",
		RoleID: "role-1", SecretIDFile: credFile(t, "secret-id", "wrong", 0o600),
		CAFile: caFile(t, srv),
	}
	if _, err := Load(context.Background(), v2); err == nil || !strings.Contains(err.Error(), "invalid role or secret ID") {
		t.Fatalf("wrong secret id: %v", err)
	}
}

func TestAVaultsRefusalIsSaidInItsWords(t *testing.T) {
	f := &fakeVault{token: "hvs.t", fields: vaultFields(), refuse: true}
	srv := httptest.NewTLSServer(f.handler())
	defer srv.Close()
	v := &Vault{Addr: srv.URL, Path: "secret/data/mdm/platform",
		TokenFile: credFile(t, "token", "hvs.t", 0o600), CAFile: caFile(t, srv)}
	_, err := Load(context.Background(), v)
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("got %v", err)
	}
	// A field the secret does not hold is named, with where to put it.
	f.refuse = false
	delete(f.fields, SessionName)
	v = &Vault{Addr: srv.URL, Path: "secret/data/mdm/platform",
		TokenFile: credFile(t, "token", "hvs.t", 0o600), CAFile: caFile(t, srv)}
	_, err = Load(context.Background(), v)
	if err == nil || !strings.Contains(err.Error(), "session_signing_key is not set") || !strings.Contains(err.Error(), "field session_signing_key of secret/data/mdm/platform") {
		t.Fatalf("missing field: %v", err)
	}
}

// The control --break-vaulthttp lets a key be fetched in the clear across
// a network. This is the test that notices.
func TestAVaultOverPlainHTTPIsRefusedExceptOnLoopback(t *testing.T) {
	token := credFile(t, "token", "hvs.t", 0o600)
	for _, addr := range []string{"http://vault.internal:8200", "http://10.0.0.5:8200"} {
		_, err := Choose(env(map[string]string{
			"MDM_KEY_SOURCE": "vault", "MDM_VAULT_ADDR": addr,
			"MDM_VAULT_PATH": "secret/data/mdm/platform", "MDM_VAULT_TOKEN_FILE": token,
		}))
		if err == nil || !strings.Contains(err.Error(), "not https") {
			t.Fatalf("%s: %v", addr, err)
		}
	}
	// Loopback is fine: a vault agent or a dev server on this machine.
	f := &fakeVault{token: "hvs.t", fields: vaultFields()}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	src, err := Choose(env(map[string]string{
		"MDM_KEY_SOURCE": "vault", "MDM_VAULT_ADDR": srv.URL,
		"MDM_VAULT_PATH": "secret/data/mdm/platform", "MDM_VAULT_TOKEN_FILE": token,
	}))
	if err != nil {
		t.Fatalf("loopback: %v", err)
	}
	if _, err := Load(context.Background(), src); err != nil {
		t.Fatalf("loopback load: %v", err)
	}
}

func TestAVaultCredentialFileMustBeOwnerOnly(t *testing.T) {
	f := &fakeVault{token: "hvs.t", fields: vaultFields()}
	srv := httptest.NewTLSServer(f.handler())
	defer srv.Close()
	v := &Vault{Addr: srv.URL, Path: "secret/data/mdm/platform",
		TokenFile: credFile(t, "token", "hvs.t", 0o644), CAFile: caFile(t, srv)}
	if _, err := Load(context.Background(), v); err == nil || !strings.Contains(err.Error(), "readable by other users") {
		t.Fatalf("got %v", err)
	}
	if f.reads != 0 {
		t.Fatal("the vault was called with a token from a readable file")
	}
}

func TestAHalfConfiguredVaultIsRefusedBeforeDialling(t *testing.T) {
	cases := []map[string]string{
		{"MDM_KEY_SOURCE": "vault"},
		{"MDM_KEY_SOURCE": "vault", "MDM_VAULT_ADDR": "https://v:8200", "MDM_VAULT_PATH": "secret/data/x"},
		{"MDM_KEY_SOURCE": "vault", "MDM_VAULT_ADDR": "https://v:8200", "MDM_VAULT_PATH": "secret/data/x", "MDM_VAULT_ROLE_ID": "r"},
		{"MDM_KEY_SOURCE": "vault", "MDM_VAULT_ADDR": "https://v:8200", "MDM_VAULT_PATH": "secret/data/x", "MDM_VAULT_TOKEN_FILE": "t", "MDM_VAULT_ROLE_ID": "r", "MDM_VAULT_SECRET_ID_FILE": "s"},
		{"MDM_KEY_SOURCE": "vault", "MDM_VAULT_ADDR": "https://v:8200", "MDM_VAULT_PATH": "secret/mdm/platform", "MDM_VAULT_TOKEN_FILE": "t"},
	}
	for _, c := range cases {
		if _, err := Choose(env(c)); err == nil {
			t.Fatalf("%v was accepted", c)
		}
	}
}
