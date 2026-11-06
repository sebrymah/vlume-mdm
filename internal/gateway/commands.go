package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"platform/internal/command"
	"platform/internal/data"
	"platform/internal/notify"
)

// ---------------------------------------------------------------- csrf
//
// The console now has forms that change things, so it needs cross-site
// request protection. Until this sprint nothing wrote and there was nothing
// to protect; that is no longer true.
//
// A token derived from the session, carried in a hidden field, checked on
// every POST. It is stateless, which keeps it simple, and it does not rotate
// per request, which is its honest limit: a token leaked from one page is
// good until the session ends.

func (g *Gateway) csrfToken(res Resolution) string {
	return g.csrfFor(res.Tenant.ID, res.Subject, string(res.Role))
}

// csrfFor is the same token computed from the three values it is actually
// derived from, so sign-out can check it while holding a session rather than
// a Resolution.
func (g *Gateway) csrfFor(tenant uuid.UUID, subject, role string) string {
	cur, _ := g.csrfKeys()
	return csrfWith(cur, tenant, subject, role)
}

func csrfWith(key []byte, tenant uuid.UUID, subject, role string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(tenant.String() + "|" + subject + "|" + role))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// csrfMatches accepts a form token under the current key or the one
// before the last rotation (0044): a form opened before the keys turned
// over still submits once.
func (g *Gateway) csrfMatches(got string, tenant uuid.UUID, subject, role string) bool {
	cur, prev := g.csrfKeys()
	if hmac.Equal([]byte(got), []byte(csrfWith(cur, tenant, subject, role))) {
		return true
	}
	return prev != nil && hmac.Equal([]byte(got), []byte(csrfWith(prev, tenant, subject, role)))
}

func (g *Gateway) csrfKeys() (current, previous []byte) {
	g.csrfMu.RLock()
	defer g.csrfMu.RUnlock()
	return g.csrfKey, g.csrfPrevious
}

// RotateCSRFKey follows the claim signing key when the platform keys are
// re-read (0044).
func (g *Gateway) RotateCSRFKey(key []byte) {
	g.csrfMu.Lock()
	defer g.csrfMu.Unlock()
	if hmac.Equal(key, g.csrfKey) {
		return
	}
	g.csrfPrevious = g.csrfKey
	g.csrfKey = append([]byte(nil), key...)
}

func (g *Gateway) csrfOK(r *http.Request, res Resolution) bool {
	got := r.FormValue("csrf")
	if got == "" {
		got = r.Header.Get("X-CSRF-Token")
	}
	if got == "" {
		return false
	}
	return g.csrfMatches(got, res.Tenant.ID, res.Subject, string(res.Role))
}

// ---------------------------------------------------------------- api

type commandBody struct {
	ID          uuid.UUID  `json:"id"`
	DeviceID    uuid.UUID  `json:"device_id"`
	Type        string     `json:"type"`
	Label       string     `json:"label"`
	State       string     `json:"state"`
	Reversible  bool       `json:"reversible"`
	Done        bool       `json:"done"`
	RequestedBy string     `json:"requested_by"`
	Reason      string     `json:"reason"`
	RequestedAt time.Time  `json:"requested_at"`
	Refused     string     `json:"refused_reason,omitempty"`
	Acked       *time.Time `json:"acknowledged_at,omitempty"`
}

func toCommandBody(c command.Command) commandBody {
	return commandBody{
		ID: c.ID, DeviceID: c.DeviceID, Type: string(c.Type), Label: c.Label(),
		State: string(c.State), Reversible: c.Reversible, Done: c.Done(),
		RequestedBy: c.RequestedBy, Reason: c.Reason, RequestedAt: c.RequestedAt,
		Refused: c.RefusedReason, Acked: c.AcknowledgedAt,
	}
}

// statusFor turns a pipeline error into an answer. The limiter gets 429
// because it is a rate control; a role refusal gets 403; a command or device
// in another tenant gets 404, never 403, for the same reason everywhere else.
func statusFor(err error) (int, string) {
	switch {
	case err == nil:
		return http.StatusOK, ""
	case errors.Is(err, command.ErrLimiterTripped):
		return http.StatusTooManyRequests,
			"bulk-wipe limiter tripped, your queue is paused and the Security Manager has been told"
	case errors.Is(err, command.ErrNotPermitted):
		return http.StatusForbidden, err.Error()
	case errors.Is(err, command.ErrNoDevice), errors.Is(err, pgx.ErrNoRows):
		return http.StatusNotFound, "no such device"
	case errors.Is(err, command.ErrWrongState):
		return http.StatusConflict, err.Error()
	case errors.Is(err, command.ErrBadNonce), errors.Is(err, command.ErrNonceUsed),
		errors.Is(err, command.ErrNonceExpired):
		return http.StatusForbidden, err.Error()
	default:
		return http.StatusBadRequest, err.Error()
	}
}

type commandInput struct {
	Scope  string `json:"scope"` // "work" or "all"
	Reason string `json:"reason"`
	Note   string `json:"note"`
}

// readInput takes the body once, as whatever it actually is.
//
// Decoding JSON first and falling back to FormValue does not work: the JSON
// decoder consumes the body, so the form parser that follows finds nothing.
// The content type says which it is, so ask that first.
func readInput(r *http.Request) commandInput {
	var in commandInput
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/x-www-form-urlencoded") ||
		strings.HasPrefix(ct, "multipart/form-data") {
		_ = r.ParseForm()
		in.Scope = r.FormValue("scope")
		in.Reason = r.FormValue("reason")
		in.Note = r.FormValue("note")
		return in
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	return in
}

func (g *Gateway) requestCommand(w http.ResponseWriter, r *http.Request, t command.Type, reason string) {
	res := ResolutionFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such device")
		return
	}
	if reason == "" {
		writeError(w, http.StatusBadRequest,
			"a reason is required and is shown to the approver")
		return
	}

	var (
		out command.Command
		// refusal is an error whose RECORD has already been written in this
		// transaction. Returning it from the closure would roll that record
		// back, which is precisely how R1's "the attempt is still recorded"
		// stopped being true the moment it went over HTTP: the unit test
		// held its own transaction open and passed, and the real path threw
		// the refusal away.
		refusal error
	)
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			c, err := g.pipe.Request(ctx, tx, command.RequestInput{
				DeviceID: id, Type: t, Reason: reason})
			out = c

			if errors.Is(err, command.ErrLimiterTripped) {
				refusal = err
				// Told in the same transaction as the refusal, so there is
				// no refusal without its notification and none without its
				// refusal. This is the line the console has been claiming
				// since the pipeline sprint.
				return g.tell(ctx, tx, notify.Message{
					Topic:   notify.LimiterTripped,
					Subject: "Bulk-wipe limiter paused a queue",
					Body: res.Subject + " asked to erase a device and has now " +
						"asked more times than the limit allows inside the window. " +
						"Their queue is paused. Reason given: " + reason,
					ObjectRef: "command:" + c.ID.String(),
					DedupeKey: "limiter:" + res.Subject,
				})
			}
			if err != nil {
				return err
			}

			// Reversible commands are approved by the asking, so they can go
			// straight out. The irreversible one waits for a second person,
			// and somebody has to be told it is waiting or dual approval
			// degrades into a queue nobody looks at.
			if c.State == command.Held {
				return g.tell(ctx, tx, notify.Message{
					Topic:   notify.ApprovalWaiting,
					Subject: c.Label() + " is waiting for a second approval",
					Body: res.Subject + " asked to " + c.Label() + ". It needs a " +
						"second person from a different role. Reason given: " + reason,
					ObjectRef: "command:" + c.ID.String(),
				})
			}
			if c.State == command.Approved {
				c, err = g.pipe.Dispatch(ctx, tx, c.ID)
				if err != nil {
					return err
				}
				out = c
			}
			return nil
		})
	if err == nil && refusal != nil {
		err = refusal
	}

	status, msg := statusFor(err)
	if err != nil {
		g.log.Warn("command refused", "type", t, "status", status, "reason", msg)
		writeJSON(w, status, map[string]any{"error": msg, "command": toCommandBody(out)})
		return
	}
	writeJSON(w, http.StatusAccepted, toCommandBody(out))
}

func (g *Gateway) lockDeviceCmd(w http.ResponseWriter, r *http.Request) {
	g.requestCommand(w, r, command.Lock, readInput(r).Reason)
}

func (g *Gateway) lostModeCmd(w http.ResponseWriter, r *http.Request) {
	g.requestCommand(w, r, command.LostMode, readInput(r).Reason)
}

func (g *Gateway) lostModeEndCmd(w http.ResponseWriter, r *http.Request) {
	g.requestCommand(w, r, command.LostModeEnd, readInput(r).Reason)
}

func (g *Gateway) wipeDevice(w http.ResponseWriter, r *http.Request) {
	in := readInput(r)

	// "work" is the default on purpose. The design rule is that the default
	// on this screen is never the one that cannot be undone.
	t := command.WipeSelective
	if in.Scope == "all" {
		t = command.WipeFull
	}
	g.requestCommand(w, r, t, in.Reason)
}

func (g *Gateway) decideCommand(approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			writeError(w, http.StatusNotFound, "no such command")
			return
		}
		in := readInput(r)

		var out command.Command
		err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
			func(ctx context.Context, tx *data.Tx) error {
				c, derr := g.pipe.Decide(ctx, tx, id,
					command.DecisionInput{Approve: approve, Note: in.Note})
				if derr != nil {
					return derr
				}
				out = c
				if approve && c.State == command.Approved {
					out, derr = g.pipe.Dispatch(ctx, tx, c.ID)
				}
				return derr
			})

		status, msg := statusFor(err)
		if err != nil {
			writeError(w, status, msg)
			return
		}
		writeJSON(w, http.StatusOK, toCommandBody(out))
	}
}

func (g *Gateway) listCommands(w http.ResponseWriter, r *http.Request) {
	f := command.Filter{OnlyHeld: r.URL.Query().Get("held") == "1"}
	if d := r.URL.Query().Get("device"); d != "" {
		if id, err := uuid.Parse(d); err == nil {
			f.DeviceID = id
		}
	}
	var out []commandBody
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			cs, err := command.List(ctx, tx, f)
			if err != nil {
				return err
			}
			out = make([]commandBody, 0, len(cs))
			for _, c := range cs {
				out = append(out, toCommandBody(c))
			}
			return nil
		})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list commands")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"commands": out})
}

// acknowledgeCommand is the device reporting back. It is reachable only on
// the device certificate path, and only for the device the command names: a
// device cannot acknowledge an instruction meant for another machine.
func (g *Gateway) acknowledgeCommand(w http.ResponseWriter, r *http.Request) {
	res := ResolutionFrom(r.Context())
	if res.Source != "device_certificate" {
		writeError(w, http.StatusForbidden, "only a device may acknowledge a command")
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such command")
		return
	}
	nonce := r.URL.Query().Get("code")
	if nonce == "" {
		nonce = r.Header.Get("X-Command-Code")
	}

	var out command.Command
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			c, lerr := command.Load(ctx, tx, id)
			if lerr != nil {
				return lerr
			}
			if c.DeviceID != res.DeviceID {
				return command.ErrNoDevice
			}
			var aerr error
			out, aerr = g.pipe.Acknowledge(ctx, tx, id, nonce)
			return aerr
		})

	status, msg := statusFor(err)
	if err != nil {
		writeError(w, status, msg)
		return
	}
	writeJSON(w, http.StatusOK, toCommandBody(out))
}

// myCommands is a device asking what it has been told to do.
//
// It is a route of its own rather than a filter on the administrator's
// listing. The administrator's listing is unscoped by design: an IT admin
// looks at the tenant's whole queue. Bolting a conditional scope onto that
// handler would mean one missed branch is a fleet-wide leak of who is being
// wiped and why. Here there is no branch to miss, because the filter is not
// built from anything the caller sent.
func (g *Gateway) myCommands(w http.ResponseWriter, r *http.Request) {
	res := ResolutionFrom(r.Context())
	if res.Source != "device_certificate" {
		writeError(w, http.StatusForbidden, "this is a device's own queue")
		return
	}

	// wait= holds the connection until there is work (F12). Capped, so a
	// gateway never holds a connection longer than a balancer would.
	wait := time.Duration(0)
	if s := r.URL.Query().Get("wait"); s != "" {
		if secs, err := strconv.Atoi(s); err == nil && secs > 0 {
			wait = time.Duration(secs) * time.Second
			if wait > maxWait {
				wait = maxWait
			}
		}
	}
	deadline := time.Now().Add(wait)

	read := func() ([]deviceCommandBody, error) {
		var out []deviceCommandBody
		err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
			func(ctx context.Context, tx *data.Tx) error {
				cs, err := command.List(ctx, tx, command.Filter{DeviceID: res.DeviceID, Limit: 50})
				if err != nil {
					return err
				}
				out = make([]deviceCommandBody, 0, len(cs))
				for _, c := range cs {
					// Only work that is actually outstanding. A device has no
					// use for the history of what it has already acknowledged,
					// and not sending it keeps the reply small on a slow link.
					if c.State != command.Queued && c.State != command.Pushed {
						continue
					}
					out = append(out, deviceCommandBody{
						commandBody: toCommandBody(c),
						Code:        deliverableCode(c, time.Now().UTC()),
						Nonce:       c.Nonce, NonceExpiresAt: c.NonceExpiresAt, Signature: c.Signature,
					})
				}
				return nil
			})
		return out, err
	}

	out, err := read()
	for err == nil && len(out) == 0 && wait > 0 {
		left := time.Until(deadline)
		if left <= 0 {
			break
		}
		if !g.waiters.await(r.Context(), res.DeviceID, left) {
			break
		}
		// Woken. The wake can arrive a moment before the command's
		// transaction commits, so look more than once, briefly.
		for i := 0; i < 10; i++ {
			if out, err = read(); err != nil || len(out) > 0 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read your commands")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"commands": out})
}

// deviceCommandBody is the administrator's view plus the one-time code.
//
// The code is in THIS type and not in commandBody, so it reaches the device
// the command names and nothing else. An administrator listing the tenant's
// queue never sees a code, which matters because a code plus a certificate
// is an acknowledgement, and an acknowledgement is the only thing the
// console reports as done.
type deviceCommandBody struct {
	commandBody
	Code string `json:"code,omitempty"`
	// What the device verifies the signature over, exactly as signed.
	Nonce          string     `json:"nonce,omitempty"`
	NonceExpiresAt *time.Time `json:"nonce_expires_at,omitempty"`
	Signature      string     `json:"signature,omitempty"`
}

// deliverableCode hands over the one-time code only while it is good for
// something. An expired or spent code is left out rather than sent and
// refused, so an agent does not carry out an instruction it then cannot
// acknowledge.
func deliverableCode(c command.Command, now time.Time) string {
	if c.Nonce == "" {
		return ""
	}
	if c.NonceExpiresAt != nil && now.After(*c.NonceExpiresAt) {
		return ""
	}
	return c.Nonce
}

// tell queues a notification inside the caller's transaction.
//
// It swallows nothing and blocks nothing: Enqueue writes a row, and the
// worker delivers it afterwards. The only way this fails is the database
// failing, in which case the event it describes is failing too and rolling
// both back together is correct.
//
// A deployment with no notifier configured gets nil, because a platform
// without notifications should still be able to request a wipe.
func (g *Gateway) tell(ctx context.Context, tx *data.Tx, m notify.Message) error {
	if g.notify == nil {
		return nil
	}
	return notify.Enqueue(ctx, tx, m)
}

// ---------------------------------------------------------------- signing keys

// mySigningKeys hands a device the public halves of its tenant's command
// signing keys, current first, with the tenant id the signature covers.
// A device verifies every instruction against these before acting; a
// signature that fits none is an instruction it does not carry out.
func (g *Gateway) mySigningKeys(w http.ResponseWriter, r *http.Request) {
	res := ResolutionFrom(r.Context())
	type key struct {
		Version      int    `json:"version"`
		PublicKeyPEM string `json:"public_key_pem"`
	}
	var keys []key
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			list, err := g.pipe.Keys().PublicKeys(ctx, tx)
			if err != nil {
				return err
			}
			for _, k := range list {
				der, err := x509.MarshalPKIXPublicKey(k.Key)
				if err != nil {
					return err
				}
				keys = append(keys, key{Version: k.Version,
					PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))})
			}
			return nil
		})
	if err != nil {
		g.log.Error("signing keys", "tenant", res.Tenant.Slug, "err", err)
		writeError(w, http.StatusInternalServerError, "the signing keys could not be read")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenant_id": res.Tenant.ID, "keys": keys})
}

// apiRotateSigningKey makes the next version. Super Admin, audited. The
// old version stays readable to devices, so nothing already signed fails.
func (g *Gateway) apiRotateSigningKey(w http.ResponseWriter, r *http.Request) {
	res := ResolutionFrom(r.Context())
	rot, ok := g.pipe.Keys().(interface {
		Rotate(context.Context, *data.Tx) (int, error)
	})
	if !ok {
		writeError(w, http.StatusNotImplemented, "this deployment's signing keys do not rotate")
		return
	}
	var version int
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			v, err := rot.Rotate(ctx, tx)
			if err != nil {
				return err
			}
			version = v
			return data.AppendAudit(ctx, tx, "signing_key.rotated", fmt.Sprintf("version:%d", v))
		})
	if err != nil {
		g.log.Error("rotate signing key", "tenant", res.Tenant.Slug, "err", err)
		writeError(w, http.StatusInternalServerError, "the signing key could not be rotated")
		return
	}
	g.log.Info("signing key rotated", "tenant", res.Tenant.Slug, "by", res.Subject, "version", version)
	writeJSON(w, http.StatusOK, map[string]any{"version": version})
}
