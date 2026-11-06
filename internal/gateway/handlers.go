package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"platform/internal/authz"
	"platform/internal/data"
	"platform/internal/policy"
)

type errorBody struct {
	Error     string `json:"error"`
	RequestID string `json:"request_id,omitempty"`
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Error: msg, RequestID: w.Header().Get("X-Request-Id")})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type deviceBody struct {
	ID           uuid.UUID  `json:"id"`
	Name         string     `json:"name"`
	Serial       string     `json:"serial"`
	OSFamily     string     `json:"os_family"`
	Ownership    string     `json:"ownership"`
	State        string     `json:"state"`
	LastReportAt *time.Time `json:"last_report_at"`
}

func toBody(d data.Device) deviceBody {
	return deviceBody{d.ID, d.Name, d.Serial, d.OSFamily, d.Ownership, d.State, d.LastReportAt}
}

func (g *Gateway) listDevices(w http.ResponseWriter, r *http.Request) {
	var out []deviceBody
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			ds, err := data.ListDevices(ctx, tx)
			if err != nil {
				return err
			}
			out = make([]deviceBody, 0, len(ds))
			for _, d := range ds {
				out = append(out, toBody(d))
			}
			return nil
		})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list devices")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

// getDevice returns 404 for a device belonging to another tenant, never 403.
//
// The application design document is explicit about this: a forbidden answer
// confirms the object exists, which is itself a cross-tenant leak. Row-level
// security makes the row invisible, so the handler cannot tell "not yours"
// from "not there", and that is the correct amount to know.
func (g *Gateway) getDevice(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such device")
		return
	}

	var found *data.Device
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			d, err := data.GetDevice(ctx, tx, id)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			found = &d
			return nil
		})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read device")
		return
	}
	if found == nil {
		writeError(w, http.StatusNotFound, "no such device")
		return
	}
	writeJSON(w, http.StatusOK, toBody(*found))
}

type auditBody struct {
	OccurredAt time.Time `json:"occurred_at"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
	ObjectRef  string    `json:"object_ref"`
	Hash       string    `json:"hash"`
}

func (g *Gateway) listAudit(w http.ResponseWriter, r *http.Request) {
	var out []auditBody
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			rows, err := tx.Query(ctx, `
				SELECT occurred_at, actor, action, coalesce(object_ref,''), hash
				  FROM audit_events ORDER BY id DESC LIMIT 100`)
			if err != nil {
				return err
			}
			defer rows.Close()
			out = []auditBody{}
			for rows.Next() {
				var a auditBody
				if err := rows.Scan(&a.OccurredAt, &a.Actor, &a.Action, &a.ObjectRef, &a.Hash); err != nil {
					return err
				}
				out = append(out, a)
			}
			return rows.Err()
		})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the audit log")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": out})
}

// home sends people where their role can actually go.
//
// An employee opening the console used to land on a dashboard they may not
// read and get a 403 on the front page, which is a product that looks broken
// rather than one that is working correctly. The dashboard is still guarded;
// this only decides which of two guarded pages to show.
func (g *Gateway) home(w http.ResponseWriter, r *http.Request) {
	res := ResolutionFrom(r.Context())
	if !authz.Can(res.Role, authz.ViewDevices) {
		http.Redirect(w, r, "/me", http.StatusFound)
		return
	}
	g.page(authz.ViewDevices, g.console.Dashboard).ServeHTTP(w, r)
}

type myDeviceBody struct {
	deviceBody
	AssignedTo     string           `json:"assigned_to"`
	ReportedLostAt *time.Time       `json:"reported_lost_at,omitempty"`
	State          string           `json:"compliance_state"`
	Findings       []policy.Finding `json:"findings"`
	Requires       []string         `json:"requires"`
}

// myDevices is the employee surface as an API, for an agent or a helpdesk
// tool acting as the person rather than as an administrator.
//
// Note what it does NOT take: an identifier for whose devices to return.
// There is nothing on this route to change to someone else's.
func (g *Gateway) myDevices(w http.ResponseWriter, r *http.Request) {
	var out []myDeviceBody
	now := time.Now().UTC()
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			ds, err := data.MyDevices(ctx, tx)
			if err != nil {
				return err
			}
			out = make([]myDeviceBody, 0, len(ds))
			for _, d := range ds {
				b := myDeviceBody{
					deviceBody: toBody(d), AssignedTo: d.AssignedTo,
					ReportedLostAt: d.ReportedLostAt,
					State:          "awaiting_first_boot",
					Findings:       []policy.Finding{},
					Requires:       []string{},
				}
				rules, _, rerr := policy.EffectiveForDevice(ctx, tx, d.ID, d.OSFamily, d.Ownership, d.Tags)
				if rerr != nil {
					return rerr
				}
				b.Requires = rules.Describe()
				if c, found, cerr := policy.Of(ctx, tx, d.ID, now); cerr != nil {
					return cerr
				} else if found {
					b.State = c.State
					b.Findings = c.Findings
				}
				out = append(out, b)
			}
			return nil
		})
	if errors.Is(err, data.ErrNotYours) {
		// A caller with no person behind it, such as a device certificate.
		writeJSON(w, http.StatusOK, map[string]any{"devices": []any{}})
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read your devices")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}
