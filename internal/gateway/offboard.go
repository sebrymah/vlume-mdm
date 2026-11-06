package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"platform/internal/command"
	"platform/internal/data"
	"platform/internal/enrol"
)

// F4: offboarding.
//
// A device is offboarded by a selective wipe through the pipeline, with its
// reason and its role, and then retired the moment the wipe is done: state
// retired, certificate revoked, slot freed. A device that never enrolled
// (no certificate, not at a vendor) has nothing to wipe and is retired at
// once. A leaver is offboarded by their address: every device assigned to
// them goes the same way, from the console, the API, or the HR system
// through a token scoped to say exactly that and nothing else.

var ErrAlreadyGone = errors.New("offboard: that device is already retired")

// offboardDevice starts one device on its way out.
func (g *Gateway) offboardDevice(ctx context.Context, tx *data.Tx, id uuid.UUID, reason, by string) (command.Command, bool, error) {
	d, err := data.GetDevice(ctx, tx, id)
	if err != nil {
		return command.Command{}, false, data.ErrNoSuchDevice
	}
	if d.Retired() {
		return command.Command{}, false, ErrAlreadyGone
	}
	if err := data.MarkOffboarding(ctx, tx, id, by); err != nil && !errors.Is(err, data.ErrNoSuchDevice) {
		return command.Command{}, false, err
	}
	// Nothing to wipe: never enrolled anywhere. Retire now.
	var certs int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM device_certificates WHERE device_id = $1 AND revoked_at IS NULL`, id).Scan(&certs); err != nil {
		return command.Command{}, false, err
	}
	var android *string
	if err := tx.QueryRow(ctx, `SELECT android_name FROM devices WHERE id = $1`, id).Scan(&android); err != nil {
		return command.Command{}, false, err
	}
	if certs == 0 && android == nil {
		return command.Command{}, true, g.retire(ctx, tx, id, "never enrolled; nothing to wipe")
	}
	c, err := g.pipe.Request(ctx, tx, command.RequestInput{DeviceID: id, Type: command.WipeSelective, Reason: reason, Offboarding: true})
	if err != nil {
		return command.Command{}, false, err
	}
	if c.State == command.Approved {
		c, err = g.pipe.Dispatch(ctx, tx, c.ID)
		if err != nil {
			return command.Command{}, false, err
		}
	}
	return c, c.State == command.Acknowledged, nil
}

// retire is the end: retired, dated, certificate revoked.
func (g *Gateway) retire(ctx context.Context, tx *data.Tx, id uuid.UUID, why string) error {
	if err := enrol.RevokeCertificates(ctx, tx, id, "retired: "+why); err != nil && !errors.Is(err, enrol.ErrBadInput) {
		return err
	}
	return data.Retire(ctx, tx, id, why)
}

// retireIfOffboarding is the pipeline's OnWiped hook: a wipe that completes
// on a device marked for offboarding retires it.
func (g *Gateway) retireIfOffboarding(ctx context.Context, tx *data.Tx, c command.Command) error {
	var offboarding bool
	if err := tx.QueryRow(ctx,
		`SELECT offboarding_at IS NOT NULL AND offboarded_at IS NULL FROM devices WHERE id = $1`,
		c.DeviceID).Scan(&offboarding); err != nil {
		return err
	}
	if !offboarding {
		return nil
	}
	return g.retire(ctx, tx, c.DeviceID, "offboarded after "+string(c.Type)+" "+c.ID.String())
}

// ---------------------------------------------------------------- one device

func (g *Gateway) apiOffboardDevice(w http.ResponseWriter, r *http.Request) {
	res := ResolutionFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such device")
		return
	}
	reason := readInput(r).Reason
	if reason == "" {
		writeError(w, http.StatusBadRequest, "a reason is required and is shown to whoever reviews this")
		return
	}
	var out command.Command
	var retired bool
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var oerr error
			out, retired, oerr = g.offboardDevice(ctx, tx, id, reason, res.Subject)
			return oerr
		})
	switch {
	case errors.Is(err, data.ErrNoSuchDevice):
		writeError(w, http.StatusNotFound, "no such device")
		return
	case errors.Is(err, ErrAlreadyGone):
		writeError(w, http.StatusConflict, "that device is already retired")
		return
	case err != nil:
		status, msg := statusFor(err)
		writeError(w, status, msg)
		return
	}
	g.log.Info("device offboarding", "tenant", res.Tenant.Slug, "device", id, "by", res.Subject, "retired", retired)
	writeJSON(w, http.StatusAccepted, map[string]any{"device_id": id, "retired": retired, "command": toCommandBody(out)})
}

func (g *Gateway) consoleOffboardDevice(w http.ResponseWriter, r *http.Request, res Resolution) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		back(w, r, "/devices", "No such device.")
		return
	}
	reason := strings.TrimSpace(r.FormValue("reason"))
	if reason == "" {
		back(w, r, "/devices/"+id.String(), "A reason is needed. It is shown to whoever reviews this.")
		return
	}
	var retired bool
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var oerr error
			_, retired, oerr = g.offboardDevice(ctx, tx, id, reason, res.Subject)
			return oerr
		})
	switch {
	case errors.Is(err, ErrAlreadyGone):
		back(w, r, "/devices/"+id.String(), "That device is already retired.")
	case err != nil:
		_, msg := statusFor(err)
		back(w, r, "/devices/"+id.String(), msg)
	case retired:
		back(w, r, "/devices/"+id.String(), "Retired. It had nothing to wipe, or the wipe is already done.")
	default:
		back(w, r, "/devices/"+id.String(), "Offboarding. Work data is being removed; the device is retired the moment that is confirmed.")
	}
}

// ---------------------------------------------------------------- a person

type offboardPersonInput struct {
	Email  string `json:"email"`
	Reason string `json:"reason"`
}

// offboardPerson is "this person has left", from a human or from HR. The
// person is found as the platform knows them (0040) and marked left, so
// their subject and address are free for the next hire and nothing of
// theirs is inherited; every device they hold is offboarded. Devices
// assigned by address before people existed are swept up as well. Someone
// the platform never met is recorded as a leaver, so HR's word is kept.
// The control --break-leftmark offboards the devices and forgets to mark
// the person.
func (g *Gateway) offboardPerson(ctx context.Context, tx *data.Tx, email, reason, by string) ([]uuid.UUID, error) {
	now := time.Now().UTC()
	person, known, err := data.FindPerson(ctx, tx, email)
	if err != nil {
		return nil, err
	}
	devs, err := data.DevicesAssignedTo(ctx, tx, email)
	if err != nil {
		return nil, err
	}
	if known {
		theirs, derr := data.DevicesOfPerson(ctx, tx, person.ID)
		if derr != nil {
			return nil, derr
		}
		devs = append(devs, theirs...)
		if err := data.MarkLeft(ctx, tx, person.ID, by, reason, now); err != nil {
			return nil, err
		}
	} else if _, err := data.RecordLeaver(ctx, tx, email, by, reason, now); err != nil {
		return nil, err
	}
	var ids []uuid.UUID
	seen := map[uuid.UUID]bool{}
	for _, d := range devs {
		if d.Offboarding() || seen[d.ID] {
			continue
		}
		seen[d.ID] = true
		if _, _, err := g.offboardDevice(ctx, tx, d.ID, reason, by); err != nil && !errors.Is(err, ErrAlreadyGone) {
			return ids, err
		}
		ids = append(ids, d.ID)
	}
	return ids, data.AppendAudit(ctx, tx, "employee.offboarded",
		"person:"+strings.ToLower(strings.TrimSpace(email))+" devices:"+itoa(len(ids))+" by:"+by)
}

func (g *Gateway) apiOffboardPerson(w http.ResponseWriter, r *http.Request) {
	res := ResolutionFrom(r.Context())
	var in offboardPersonInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil ||
		strings.TrimSpace(in.Email) == "" {
		writeError(w, http.StatusBadRequest, "say who has left: their address, as devices are assigned")
		return
	}
	if strings.TrimSpace(in.Reason) == "" {
		in.Reason = "left the organisation"
	}
	var ids []uuid.UUID
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var oerr error
			ids, oerr = g.offboardPerson(ctx, tx, in.Email, in.Reason, res.Subject)
			return oerr
		})
	if err != nil {
		status, msg := statusFor(err)
		writeError(w, status, msg)
		return
	}
	g.log.Info("person offboarded", "tenant", res.Tenant.Slug, "devices", len(ids), "by", res.Subject)
	writeJSON(w, http.StatusAccepted, map[string]any{"devices": ids, "count": len(ids)})
}

func (g *Gateway) consoleOffboardPerson(w http.ResponseWriter, r *http.Request, res Resolution) {
	email := strings.TrimSpace(r.FormValue("email"))
	reason := strings.TrimSpace(r.FormValue("reason"))
	returnTo := "/devices"
	// From a person's own page: the person by id, named by whatever the
	// platform knows them as.
	if pid, perr := uuid.Parse(r.FormValue("person")); perr == nil {
		returnTo = "/people/" + pid.String()
		err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
			func(ctx context.Context, tx *data.Tx) error {
				p, gerr := data.GetPerson(ctx, tx, pid)
				if gerr != nil {
					return gerr
				}
				email = p.Email
				if email == "" {
					email = p.Subject
				}
				return nil
			})
		if err != nil {
			back(w, r, "/people", "No such person.")
			return
		}
	}
	if email == "" {
		back(w, r, returnTo, "Say who has left.")
		return
	}
	if reason == "" {
		reason = "left the organisation"
	}
	var ids []uuid.UUID
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var oerr error
			ids, oerr = g.offboardPerson(ctx, tx, email, reason, res.Subject)
			return oerr
		})
	if err != nil {
		_, msg := statusFor(err)
		back(w, r, returnTo, msg)
		return
	}
	back(w, r, returnTo, itoa(len(ids))+" device(s) assigned to "+email+" are being offboarded.")
}
