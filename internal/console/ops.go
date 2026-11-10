package console

import (
	"html/template"
	"net/http"
	"time"

	"platform/internal/directory"
)

// The platform owner's console. It is not an organisation's console with
// another role: it has its own pages, its own colours (no organisation's
// brand ever appears on it), its own sign-in, and it is served only on its
// own hostname. It shows what the owner's database role may read and nothing
// else: organisations as a shell, usage as counts, never a device, a person or
// a policy.

// OpsNav is one entry of the owner's menu.
type OpsNav struct {
	Label, Href string
	Active      bool
}

// OpsWho is the signed-in owner.
type OpsWho struct{ Email, Name string }

// OpsOrg is one organisation as the owner sees it: the shell and the counts.
type OpsOrg struct {
	directory.Summary
	Devices, DeviceCap int
	Seats, SeatCap     int
	// Percent is the share of the device allowance in use, and Flag says "near"
	// from 80 percent and "over" from 100.
	Percent int
	Flag    string
	// NoUsage is true when the counts could not be read. Unknown is not zero.
	NoUsage bool
}

// OpsDash is the front page.
type OpsDash struct {
	Orgs, Active, Suspended, Other  int
	PendingSignups, FinishedSignups int
	Devices                         int
	NewWeek, NewMonth               int
	NearCap                         int
	ByPlan                          []OpsCount
	Newest                          []OpsOrg
	RecentSignups                   []directory.SignupRow
}

// OpsCount is a label and how many.
type OpsCount struct {
	Label string
	N     int
}

// OpsOrgDetail is one organisation's page.
type OpsOrgDetail struct {
	OpsOrg
	Tenant   directory.Tenant
	Features []OpsFeature
	History  []directory.Snapshot
	Usage    directory.Usage
	Plans    []directory.Plan
}

// OpsFeature is a feature switch and where its answer comes from.
type OpsFeature struct {
	Name      string
	On        bool
	FromPlan  bool // true when the plan's default is what applies
	PlanValue bool
}

// OpsOperator is one owner account in the list of owners.
type OpsOperator struct {
	directory.Operator
	You bool
}

// OpsView is everything an owner page can show. Page names the template.
type OpsView struct {
	Page, Title  string
	Said, Notice string
	Who          *OpsWho
	CSRF         string
	Nav          []OpsNav
	Now          time.Time

	// Sign-in pages.
	Email  string
	Name   string
	Secret string
	QR     template.URL
	Codes  []string
	Next   string

	// Content pages.
	Dash      *OpsDash
	Orgs      []OpsOrg
	Query     string
	Filter    string
	Org       *OpsOrgDetail
	Signups   []directory.SignupRow
	Plans     []directory.Plan
	Operators []OpsOperator
	Events    []directory.OperatorEventRow
	// NewLink is an invitation or reset link just made, shown once.
	NewLink    string
	NewLinkFor string
}

// OpsNavFor is the menu, with the current page marked.
func OpsNavFor(active string) []OpsNav {
	items := []OpsNav{
		{"Overview", "/", false}, {"Organisations", "/orgs", false}, {"Sign-ups", "/signups", false},
		{"Licences", "/licences", false}, {"Owners", "/operators", false}, {"Activity", "/events", false},
		{"Account", "/account", false},
	}
	for i := range items {
		items[i].Active = items[i].Href == active
	}
	return items
}

// RenderOps writes an owner page. Nothing here is cached and nothing may be
// framed: the pages carry an owner's session and the controls that act on
// every customer.
func RenderOps(w http.ResponseWriter, status int, v OpsView) {
	v.Now = time.Now()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	// same-origin, not no-referrer: with no-referrer Safari sends the form's
	// Origin as "null", which the same-origin check rightly refuses. Nothing
	// leaves this site in a Referer either way.
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.WriteHeader(status)
	if err := tmpl.ExecuteTemplate(w, v.Page, v); err != nil {
		http.Error(w, "This page could not be shown.", status)
	}
}
