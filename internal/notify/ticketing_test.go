package notify

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// F20. A message becomes a Jira issue or a ServiceNow incident, with the
// tool's own authentication and shape; the endpoint is checked when it is
// typed; and the client dials nothing inside this platform's network.

func fakeTool(t *testing.T, kind string) (*httptest.Server, *[]map[string]any, *string) {
	t.Helper()
	var got []map[string]any
	var auth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		m["_path"] = r.URL.Path
		got = append(got, m)
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"key":"OPS-1"}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &got, &auth
}

func TestJiraAndServiceNowGetATicketInTheirOwnShape(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	msg := Message{Topic: ApprovalWaiting, Subject: "Erase everything is waiting for a second approval",
		Body: "o.martins asked to erase HQ-MBP-001.", ObjectRef: "command:abc"}

	jiraSrv, jiraGot, jiraAuth := fakeTool(t, "jira")
	jira := NewTicketing("jira", log)
	jira.AllowPrivateAddresses = true
	jira.client.Transport.(*http.Transport).TLSClientConfig = jiraSrv.Client().Transport.(*http.Transport).TLSClientConfig
	cfg := `{"url":"` + jiraSrv.URL + `","user":"bot@kalesi.example","token":"tok","project":"OPS"}`
	if err := jira.Deliver(context.Background(), cfg, msg); err != nil {
		t.Fatalf("jira: %v", err)
	}
	if len(*jiraGot) != 1 || (*jiraGot)[0]["_path"] != "/rest/api/3/issue" {
		t.Fatalf("jira got %v", *jiraGot)
	}
	fields := (*jiraGot)[0]["fields"].(map[string]any)
	if fields["summary"] != msg.Subject || fields["project"].(map[string]any)["key"] != "OPS" {
		t.Fatalf("jira fields: %v", fields)
	}
	if !strings.HasPrefix(*jiraAuth, "Basic ") {
		t.Fatalf("jira auth: %q", *jiraAuth)
	}

	snowSrv, snowGot, _ := fakeTool(t, "servicenow")
	snow := NewTicketing("servicenow", log)
	snow.AllowPrivateAddresses = true
	snow.client.Transport.(*http.Transport).TLSClientConfig = snowSrv.Client().Transport.(*http.Transport).TLSClientConfig
	cfg = `{"url":"` + snowSrv.URL + `","user":"api","token":"tok"}`
	if err := snow.Deliver(context.Background(), cfg, msg); err != nil {
		t.Fatalf("servicenow: %v", err)
	}
	if len(*snowGot) != 1 || (*snowGot)[0]["_path"] != "/api/now/table/incident" || (*snowGot)[0]["short_description"] != msg.Subject {
		t.Fatalf("servicenow got %v", *snowGot)
	}
}

func TestATicketingDestinationIsCheckedWhenTypedAndNeverInternal(t *testing.T) {
	for _, bad := range []string{
		`not json`, `{"url":"http://jira.example","user":"u","token":"t","project":"OPS"}`,
		`{"url":"https://jira.example","user":"","token":"t","project":"OPS"}`,
		`{"url":"https://jira.example","user":"u","token":"t"}`,
		`{"url":"https://jira.example/?x=1","user":"u","token":"t","project":"OPS"}`,
	} {
		if _, err := ParseTicketConfig("jira", bad); err == nil {
			t.Fatalf("accepted: %s", bad)
		}
	}
	if _, err := ParseTicketConfig("servicenow", `{"url":"https://now.example","user":"u","token":"t","table":"incident; drop"}`); err == nil {
		t.Fatal("a bad table name was accepted")
	}
	// A private address, with the guard on, is refused at dial time.
	srv, _, _ := fakeTool(t, "jira")
	guarded := NewTicketing("jira", slog.New(slog.NewTextHandler(io.Discard, nil)))
	guarded.client.Transport.(*http.Transport).TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig
	cfg := `{"url":"` + srv.URL + `","user":"u","token":"t","project":"OPS"}`
	err := guarded.Deliver(context.Background(), cfg, Message{Topic: DeviceLost, Subject: "x"})
	if err == nil || !strings.Contains(err.Error(), "inside this platform") {
		t.Fatalf("a ticketing request reached a private address: %v", err)
	}
}
