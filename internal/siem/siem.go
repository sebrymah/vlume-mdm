// Package siem is F19: the audit log, forwarded as a stream to the tenant's
// SIEM in CEF or LEEF over syslog, or as JSON to a webhook.
//
// The destination is the ordinary notification target for topic
// siem.audit. The position is a cursor per tenant that moves only after
// the collector has taken the event. A failed send stops the run with the
// cursor where it was; the next run starts from there, so the stream has
// no gaps and no repeats.
package siem

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"platform/internal/branding"
	"platform/internal/data"
	"platform/internal/notify"
)

type Event struct {
	ID         int64
	OccurredAt time.Time
	Actor      string
	Action     string
	ObjectRef  string
	Hash       string
}

// Severity on CEF's 0 to 10: a wipe is 8, an enforcement 6, a failed
// authentication 5, the rest 3.
func severity(action string) int {
	switch {
	case strings.HasPrefix(action, "wipe") || strings.Contains(action, "wipe"):
		return 8
	case strings.Contains(action, "quarantin") || strings.Contains(action, "lock") || strings.Contains(action, "lost"):
		return 6
	case strings.Contains(action, "rejected") || strings.Contains(action, "refused") || strings.Contains(action, "halted"):
		return 5
	}
	return 3
}

func cefHeader(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, "|", `\|`)
}

func cefExt(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "=", `\=`)
	return strings.ReplaceAll(s, "\n", " ")
}

// CEF renders one event. The vendor field is the TENANT's product name:
// the SIEM is the tenant's, and what it shows its analysts is the tenant's
// own product, never ours (T12 applies to a log line as to a page).
func CEF(e Event, b branding.Brand, slug string) string {
	return fmt.Sprintf("CEF:0|%s|Device Management|1|%s|%s|%d|rt=%d suser=%s act=%s cs1Label=object cs1=%s cs2Label=tenant cs2=%s cn1Label=auditId cn1=%d cs3Label=hash cs3=%s",
		cefHeader(vendor(b)), cefHeader(e.Action), cefHeader(words(e.Action)), severity(e.Action),
		e.OccurredAt.UnixMilli(), cefExt(e.Actor), cefExt(e.Action), cefExt(e.ObjectRef), cefExt(slug), e.ID, cefExt(e.Hash))
}

// LEEF is the other dialect, for QRadar and its relatives.
func LEEF(e Event, b branding.Brand, slug string) string {
	return fmt.Sprintf("LEEF:2.0|%s|Device Management|1|%s|^|devTime=%s^devTimeFormat=yyyy-MM-dd'T'HH:mm:ss'Z'^usrName=%s^action=%s^object=%s^tenant=%s^auditId=%d^hash=%s^sev=%d",
		cefHeader(vendor(b)), cefHeader(e.Action), e.OccurredAt.UTC().Format("2006-01-02T15:04:05Z"),
		leef(e.Actor), leef(e.Action), leef(e.ObjectRef), leef(slug), e.ID, leef(e.Hash), severity(e.Action))
}

func leef(s string) string { return strings.NewReplacer("^", " ", "\n", " ").Replace(s) }

func vendor(b branding.Brand) string {
	if b.IsPlaceholder() {
		return "Device Management"
	}
	return b.ProductName
}

// words turns an action into something an analyst reads.
func words(action string) string {
	return strings.NewReplacer(".", " ", "_", " ").Replace(action)
}

// Result is the in-vs-out block for one run.
type Result struct {
	From, To  int64
	Sent      int
	Remaining int
	Err       error
}

// Export ships the next batch. The cursor moves one event at a time, after
// each successful send, so a failure half way through keeps what was sent
// and resumes from the failure.
func Export(ctx context.Context, tx *data.Tx, svc *notify.Service, slug string, limit int) (Result, error) {
	var res Result
	if limit <= 0 {
		limit = 200
	}
	target, err := svc.TargetFor(ctx, tx, notify.SIEMAudit)
	if errors.Is(err, notify.ErrNoTarget) {
		return res, nil // nothing listening; nothing owed
	}
	if err != nil {
		return res, err
	}
	b, err := branding.Load(ctx, tx)
	if err != nil {
		return res, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO siem_cursors (tenant_id) VALUES (app.current_tenant())
		ON CONFLICT (tenant_id) DO NOTHING`); err != nil {
		return res, err
	}
	var cursor int64
	if err := tx.QueryRow(ctx, `SELECT last_audit_id FROM siem_cursors`).Scan(&cursor); err != nil {
		return res, err
	}
	res.From = cursor

	rows, err := tx.Query(ctx, `
		SELECT id, occurred_at, actor, action, coalesce(object_ref,''), hash
		  FROM audit_events WHERE id > $1 ORDER BY id LIMIT $2`, cursor, limit+1)
	if err != nil {
		return res, err
	}
	var events []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.OccurredAt, &e.Actor, &e.Action, &e.ObjectRef, &e.Hash); err != nil {
			rows.Close()
			return res, err
		}
		events = append(events, e)
	}
	rows.Close()
	if len(events) > limit {
		res.Remaining = len(events) - limit
		events = events[:limit]
	}

	format := "cef"
	if target.Kind == "syslog" {
		if ep, err := notify.ParseSyslog(target.Endpoint); err == nil {
			format = ep.Format
		}
	}
	for _, e := range events {
		line := CEF(e, b, slug)
		if format == "leef" {
			line = LEEF(e, b, slug)
		}
		m := notify.Message{
			Topic: notify.SIEMAudit, Subject: e.Action + " " + e.ObjectRef, Body: line,
			ObjectRef: fmt.Sprintf("audit:%d", e.ID), Tenant: vendor(b),
		}
		if err := svc.DeliverNow(ctx, target, m); err != nil {
			res.Err = err
			_, _ = tx.Exec(ctx, `UPDATE siem_cursors SET last_error = $1`, err.Error())
			return res, nil
		}
		// Taken. Move the cursor past it, and only it.
		if _, err := tx.Exec(ctx, `
			UPDATE siem_cursors
			   SET last_audit_id = $1, sent_total = sent_total + 1, last_sent_at = now(), last_error = NULL`,
			e.ID); err != nil {
			return res, err
		}
		res.Sent++
		res.To = e.ID
	}
	return res, nil
}

// Cursor is what the page shows: where the stream is and when it last moved.
type Cursor struct {
	LastAuditID int64
	SentTotal   int64
	LastSentAt  *time.Time
	LastError   string
	Behind      int64
}

func Status(ctx context.Context, tx *data.Tx) (Cursor, error) {
	var c Cursor
	err := tx.QueryRow(ctx, `
		SELECT coalesce(s.last_audit_id, 0), coalesce(s.sent_total, 0), s.last_sent_at, coalesce(s.last_error, ''),
		       (SELECT count(*) FROM audit_events a WHERE a.id > coalesce(s.last_audit_id, 0))
		  FROM (SELECT 1) one LEFT JOIN siem_cursors s ON true`).Scan(
		&c.LastAuditID, &c.SentTotal, &c.LastSentAt, &c.LastError, &c.Behind)
	return c, err
}
