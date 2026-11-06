package platformkeys

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Vault reads the keys from one secret in HashiCorp Vault's KV version 2
// store, over its HTTP API and nothing else: no client library, so the
// whole exchange is on this page. The secret holds the four names as
// fields. Authentication is a token read from an owner-only file, or an
// AppRole (role id in the environment, secret id in an owner-only file)
// that is logged in once to get a token.
//
// The address is https. Plain http is allowed to a loopback address and
// nowhere else: a key fetched in the clear across a network is a key
// anyone on the network has.
type Vault struct {
	// Addr is the server, https://vault.example:8200.
	Addr string
	// Path is the KV v2 read path, secret/data/mdm/platform.
	Path string
	// Namespace is for Vault Enterprise; empty otherwise.
	Namespace string
	// TokenFile holds a token, owner-only. Or an AppRole:
	TokenFile    string
	RoleID       string
	SecretIDFile string
	// CAFile trusts a private authority for the vault's certificate;
	// empty means the system's roots.
	CAFile  string
	Timeout time.Duration

	once   sync.Once
	fields map[string]string
	err    error
}

func (v *Vault) Name() string { return "vault " + v.Addr + " at " + v.Path }

func (v *Vault) Where(name string) string { return "field " + name + " of " + v.Path + " in " + v.Addr }

// check refuses a configuration that could not work, or that would send
// a token or a key across the network in the clear, before anything is
// dialled.
func (v *Vault) check() error {
	if v.Addr == "" || v.Path == "" {
		return errors.New("platformkeys: MDM_VAULT_ADDR and MDM_VAULT_PATH are both needed for MDM_KEY_SOURCE=vault")
	}
	u, err := url.Parse(v.Addr)
	if err != nil || u.Host == "" {
		return fmt.Errorf("platformkeys: MDM_VAULT_ADDR %q is not an address", v.Addr)
	}
	if u.Scheme != "https" && !loopback(u.Hostname()) {
		return fmt.Errorf("platformkeys: MDM_VAULT_ADDR %q is not https; keys are not fetched in the clear across a network", v.Addr)
	}
	if !strings.Contains(v.Path, "/data/") {
		return fmt.Errorf("platformkeys: MDM_VAULT_PATH %q is not a KV v2 read path (it looks like secret/data/mdm/platform)", v.Path)
	}
	hasToken := v.TokenFile != ""
	hasRole := v.RoleID != "" || v.SecretIDFile != ""
	switch {
	case hasToken && hasRole:
		return errors.New("platformkeys: set MDM_VAULT_TOKEN_FILE or MDM_VAULT_ROLE_ID with MDM_VAULT_SECRET_ID_FILE, not both")
	case hasRole && (v.RoleID == "" || v.SecretIDFile == ""):
		return errors.New("platformkeys: an AppRole needs both MDM_VAULT_ROLE_ID and MDM_VAULT_SECRET_ID_FILE")
	case !hasToken && !hasRole:
		return errors.New("platformkeys: the vault needs MDM_VAULT_TOKEN_FILE, or MDM_VAULT_ROLE_ID with MDM_VAULT_SECRET_ID_FILE")
	}
	return nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (v *Vault) Read(ctx context.Context, name string) ([]byte, error) {
	v.once.Do(func() { v.fields, v.err = v.fetch(ctx) })
	if v.err != nil {
		return nil, v.err
	}
	text, ok := v.fields[name]
	if !ok || text == "" {
		return nil, ErrNotFound
	}
	return decode(text)
}

// fetch reads the secret once. Every key comes from the one read, so the
// four cannot come from two different versions of the secret.
func (v *Vault) fetch(ctx context.Context) (map[string]string, error) {
	if err := v.check(); err != nil {
		return nil, err
	}
	client, err := v.client()
	if err != nil {
		return nil, err
	}
	token, err := v.token(ctx, client)
	if err != nil {
		return nil, err
	}
	var out struct {
		Data struct {
			Data     map[string]string `json:"data"`
			Metadata struct {
				Version int `json:"version"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if err := v.call(ctx, client, http.MethodGet, "/v1/"+strings.Trim(v.Path, "/"), token, nil, &out); err != nil {
		return nil, err
	}
	if out.Data.Data == nil {
		return nil, fmt.Errorf("platformkeys: %s holds no data; is it a KV v2 secret?", v.Path)
	}
	return out.Data.Data, nil
}

// token is the token file's contents, or the result of an AppRole login.
func (v *Vault) token(ctx context.Context, client *http.Client) (string, error) {
	if v.TokenFile != "" {
		b, err := ownerOnly(v.TokenFile)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	secretID, err := ownerOnly(v.SecretIDFile)
	if err != nil {
		return "", err
	}
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	body := map[string]string{"role_id": v.RoleID, "secret_id": strings.TrimSpace(string(secretID))}
	if err := v.call(ctx, client, http.MethodPost, "/v1/auth/approle/login", "", body, &out); err != nil {
		return "", err
	}
	if out.Auth.ClientToken == "" {
		return "", errors.New("platformkeys: the AppRole login answered without a token")
	}
	return out.Auth.ClientToken, nil
}

// ownerOnly reads a file that holds a credential, refusing one other
// users can read: the same rule the agent's enrolment token file follows.
func ownerOnly(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("platformkeys: %w", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("platformkeys: %s is readable by other users (mode %04o); a credential file is owner-only (chmod 0600)", path, perm)
	}
	return os.ReadFile(path)
}

func (v *Vault) client() (*http.Client, error) {
	timeout := v.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if v.CAFile != "" {
		pem, err := os.ReadFile(v.CAFile)
		if err != nil {
			return nil, fmt.Errorf("platformkeys: MDM_VAULT_CA_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("platformkeys: MDM_VAULT_CA_FILE holds no certificate")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Transport: tr, Timeout: timeout}, nil
}

// call is one request to the vault. The answer is read up to a megabyte
// and its errors array, when there is one, is what the person sees.
func (v *Vault) call(ctx context.Context, client *http.Client, method, path, token string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(v.Addr, "/")+path, rd)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if v.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", v.Namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("platformkeys: the vault could not be reached: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("platformkeys: reading the vault's answer: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Errors []string `json:"errors"`
		}
		_ = json.Unmarshal(raw, &e)
		if len(e.Errors) > 0 {
			return fmt.Errorf("platformkeys: the vault refused %s: %s", path, strings.Join(e.Errors, "; "))
		}
		return fmt.Errorf("platformkeys: the vault answered %s with HTTP %d", path, resp.StatusCode)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("platformkeys: the vault's answer to %s was not understood: %w", path, err)
	}
	return nil
}
