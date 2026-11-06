package gateway

import (
	"bytes"
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"platform/internal/authz"
	"platform/internal/branding"
	"platform/internal/console"
	"platform/internal/data"
	"platform/internal/notify"
	"platform/internal/report"
	"platform/internal/tenantclaim"
)

// F18: the compliance report, as a download and on a schedule.
//
// A report is an export of tenant data. It is built under the tenant's
// claim, it is audited when it is made, and it carries the tenant's brand.
// Who may make one is who may see devices, which includes the auditor,
// because a report is what an auditor is for.

func (g *Gateway) complianceReport(ctx context.Context, tx *data.Tx, format, by string) ([]byte, string, error) {
	now := time.Now().UTC()
	rep, err := report.Compliance(ctx, tx, now)
	if err != nil {
		return nil, "", err
	}
	b, err := branding.Load(ctx, tx)
	if err != nil {
		return nil, "", err
	}
	var buf bytes.Buffer
	switch format {
	case "csv":
		err = report.CSV(&buf, rep)
	default:
		format = "pdf"
		var logo *report.Logo
		if lb, typ, ok, lerr := branding.Image(ctx, tx, "logo"); lerr == nil && ok {
			logo = report.DecodeLogo(lb, typ)
		}
		err = report.PDFWithLogo(&buf, rep, b, "Compliance report", logo)
	}
	if err != nil {
		return nil, "", err
	}
	if err := data.AppendAudit(ctx, tx, "report.generated", "compliance."+format+" devices:"+itoa(rep.Total)); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), report.Filename(b, now, format), nil
}

func (g *Gateway) serveReport(w http.ResponseWriter, r *http.Request, format string) {
	res := ResolutionFrom(r.Context())
	var body []byte
	var name string
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var rerr error
			body, name, rerr = g.complianceReport(ctx, tx, format, res.Subject)
			return rerr
		})
	if err != nil {
		g.log.Error("report", "format", format, "err", err)
		writeError(w, http.StatusInternalServerError, "the report could not be made")
		return
	}
	g.log.Info("report generated", "tenant", res.Tenant.Slug, "format", format, "by", res.Subject)
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "application/pdf")
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

func (g *Gateway) reportCSV(w http.ResponseWriter, r *http.Request) { g.serveReport(w, r, "csv") }
func (g *Gateway) reportPDF(w http.ResponseWriter, r *http.Request) { g.serveReport(w, r, "pdf") }

func (g *Gateway) apiReport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format != "csv" {
		format = "pdf"
	}
	g.serveReport(w, r, format)
}

func (g *Gateway) consoleReports(w http.ResponseWriter, r *http.Request, s console.Session) {
	g.console.ReportsPage(w, r, s, func(ctx context.Context, tx *data.Tx, out *console.Reports) error {
		rep, err := report.Compliance(ctx, tx, time.Now().UTC())
		if err != nil {
			return err
		}
		out.Summary = rep.Summary()
		out.Total = rep.Total
		targets, err := g.notify.Targets(ctx, tx)
		if err != nil {
			return err
		}
		for _, t := range targets {
			if t.Topic == notify.ReportCompliance {
				out.Scheduled = t.Redacted()
			}
		}
		return nil
	})
}

// ---------------------------------------------------------------- scheduled

// WeeklyReport is the scheduled half of F18: once a week, the summary and
// a link to the download, through whatever channel the tenant pointed the
// report.compliance topic at. Once per ISO week per tenant, so a sweep
// that runs daily sends on its first run of the week and not again.
func (g *Gateway) WeeklyReport(ctx context.Context, tx *data.Tx, host string, now time.Time) (bool, error) {
	rep, err := report.Compliance(ctx, tx, now)
	if err != nil {
		return false, err
	}
	year, week := now.ISOWeek()
	key := "report.compliance:" + itoa(year) + "-W" + itoa(week)
	b, err := branding.Load(ctx, tx)
	if err != nil {
		return false, err
	}
	link := "https://" + host + "/reports/compliance.pdf"
	m := notify.Message{
		Topic:   notify.ReportCompliance,
		Subject: "Weekly compliance report: " + rep.Summary(),
		Body: b.ProductName + " compliance this week.\n\n" + rep.Summary() + ".\n\n" +
			"The full report, as PDF or CSV, is on the console's Reports page: " + link + "\n",
		ObjectRef: "report:" + key, DedupeKey: key, Once: true,
	}
	before, err := countKey(ctx, tx, key)
	if err != nil {
		return false, err
	}
	if err := notify.Enqueue(ctx, tx, m); err != nil {
		return false, err
	}
	after, err := countKey(ctx, tx, key)
	return after > before, err
}

func countKey(ctx context.Context, tx *data.Tx, key string) (int, error) {
	var n int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE dedupe_key = $1`, key).Scan(&n)
	return n, err
}

// RunWeeklyReport sweeps every tenant on the interval; WeeklyReport's
// once-per-week key makes the interval a matter of latency, not of count.
func (g *Gateway) RunWeeklyReport(ctx context.Context, tenants func(context.Context) ([]uuid.UUID, error),
	hostOf func(context.Context, uuid.UUID) (string, error), every time.Duration) {
	if every <= 0 {
		every = 24 * time.Hour
	}
	g.log.Info("weekly report sweep running", "every", every)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
		ids, err := tenants(ctx)
		if err != nil {
			g.log.Error("report sweep: could not list tenants", "err", err)
			continue
		}
		for _, id := range ids {
			host, err := hostOf(ctx, id)
			if err != nil {
				continue
			}
			claim, err := g.signer.Mint(tenantclaim.Claim{
				TenantID: id, Subject: "system:weekly-report",
				Role: string(authz.Operator), RequestID: uuid.NewString(),
			}, 2*time.Minute)
			if err != nil {
				continue
			}
			if err := g.store.WithTenant(ctx, claim, func(ctx context.Context, tx *data.Tx) error {
				sent, serr := g.WeeklyReport(ctx, tx, host, time.Now().UTC())
				if serr == nil && sent {
					g.log.Info("weekly report queued", "tenant", id)
				}
				return serr
			}); err != nil {
				g.log.Error("weekly report", "tenant", id, "err", err)
			}
		}
	}
}

// RunUsageSnapshots is T9's history: one snapshot per tenant per day,
// taken through the operator's directory so the application role never
// needs a grant on the billing table.
func RunUsageSnapshots(ctx context.Context, record func(context.Context, time.Time) (int, error),
	every time.Duration, log interface {
		Info(string, ...any)
		Error(string, ...any)
	}) {
	if every <= 0 {
		every = 6 * time.Hour
	}
	for {
		if n, err := record(ctx, time.Now()); err != nil {
			log.Error("usage snapshots", "err", err)
		} else if n > 0 {
			log.Info("usage snapshots taken", "tenants", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}
