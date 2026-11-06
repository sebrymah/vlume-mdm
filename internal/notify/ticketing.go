package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// F20: ticketing. A Jira issue or a ServiceNow incident per message,
// through the same outbox and retries as every other channel. The
// endpoint is the integration's configuration as JSON; it carries a
// token, and is sealed like every endpoint.
//
// Same dial guard as the webhook channel: the URL is a tenant
// administrator's, and a request made from in here must not reach this
// platform's own internals.

type Ticketing struct {
	kind                  string
	log                   *slog.Logger
	client                *http.Client
	AllowPrivateAddresses bool
}

// TicketConfig is what a tenant types: where, how to authenticate, and
// where in the tool the ticket lands.
type TicketConfig struct {
	URL   string `json:"url"`
	User  string `json:"user"`
	Token string `json:"token"`
	// Jira: the project key. ServiceNow: the table (incident by default).
	Project string `json:"project,omitempty"`
	Table   string `json:"table,omitempty"`
	// Jira only: the issue type name. "Task" by default.
	IssueType string `json:"issue_type,omitempty"`
}

func NewTicketing(kind string, log *slog.Logger) *Ticketing {
	t := &Ticketing{kind: kind, log: log}
	t.client = &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 5 * time.Second,
				Control: func(_, address string, _ syscall.RawConn) error {
					return t.allowAddress(address)
				},
			}).DialContext,
			TLSHandshakeTimeout: 5 * time.Second,
		},
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return fmt.Errorf("%w: a ticketing endpoint does not redirect", ErrBadEndpoint)
		},
	}
	return t
}

func (t *Ticketing) Name() string { return t.kind }

func (t *Ticketing) allowAddress(address string) error {
	if t.AllowPrivateAddresses {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrBadEndpoint, address)
	}
	ip := net.ParseIP(host)
	if ip == nil || !publicIP(ip) {
		return fmt.Errorf("%w: that endpoint resolves to an address inside this platform's own network", ErrBadEndpoint)
	}
	return nil
}

// ParseTicketConfig reads and checks the configuration.
func ParseTicketConfig(kind, endpoint string) (TicketConfig, error) {
	var c TicketConfig
	if err := json.Unmarshal([]byte(strings.TrimSpace(endpoint)), &c); err != nil {
		return c, fmt.Errorf("%w: a %s destination is JSON with url, user, token and %s", ErrBadEndpoint, kind, ticketField(kind))
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return c, fmt.Errorf("%w: url is the https address of your %s instance, nothing more", ErrBadEndpoint, kind)
	}
	c.URL = strings.TrimSuffix(c.URL, "/")
	if strings.TrimSpace(c.User) == "" || strings.TrimSpace(c.Token) == "" {
		return c, fmt.Errorf("%w: user and token are both needed", ErrBadEndpoint)
	}
	switch kind {
	case "jira":
		if strings.TrimSpace(c.Project) == "" {
			return c, fmt.Errorf("%w: project is the Jira project key", ErrBadEndpoint)
		}
		if c.IssueType == "" {
			c.IssueType = "Task"
		}
	case "servicenow":
		if c.Table == "" {
			c.Table = "incident"
		}
		for _, r := range c.Table {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '_' {
				return c, fmt.Errorf("%w: table is a ServiceNow table name", ErrBadEndpoint)
			}
		}
	default:
		return c, fmt.Errorf("%w: unknown ticketing kind %q", ErrBadEndpoint, kind)
	}
	return c, nil
}

func ticketField(kind string) string {
	if kind == "jira" {
		return "project"
	}
	return "table"
}

func (t *Ticketing) Deliver(ctx context.Context, endpoint string, m Message) error {
	c, err := ParseTicketConfig(t.kind, endpoint)
	if err != nil {
		return err
	}
	var path string
	var payload any
	description := m.Body + "\n\n[" + string(m.Topic) + " " + m.ObjectRef + "]"
	switch t.kind {
	case "jira":
		path = "/rest/api/3/issue"
		payload = map[string]any{"fields": map[string]any{
			"project":   map[string]string{"key": c.Project},
			"issuetype": map[string]string{"name": c.IssueType},
			"summary":   clipTicket(m.Subject, 250),
			"description": map[string]any{"type": "doc", "version": 1, "content": []any{
				map[string]any{"type": "paragraph", "content": []any{
					map[string]any{"type": "text", "text": description}}}}},
			"labels": []string{"device-management", strings.ReplaceAll(string(m.Topic), ".", "-")},
		}}
	case "servicenow":
		path = "/api/now/table/" + c.Table
		payload = map[string]any{
			"short_description": clipTicket(m.Subject, 160),
			"description":       description,
			"category":          "security",
			"correlation_id":    m.ObjectRef,
		}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.URL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadEndpoint, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(c.User, c.Token)
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s answered %d: %s", t.kind, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}

func clipTicket(s string, n int) string {
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}
