// Package command is the pipeline every outbound instruction passes through.
//
// F12 to F15 are the instructions themselves. The rules around them are the
// product: R1 the bulk-wipe limiter, R4 signing with a one-time code that
// expires, R6 two approvals from two distinct roles for a full wipe, R8
// RSA-SHA256 on everything that leaves.
//
// Two design rules from the application design document are enforced here
// rather than left to callers:
//
//   - Pushed is never reported as success. Only Acknowledged means the device
//     ran it, and that is the state the console shows.
//   - An expired command is never retried automatically. A wipe that arrives
//     an hour after everyone assumed it had failed is worse than one that
//     never arrived.
package command

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"platform/internal/authz"
	"platform/internal/data"
)

type Type string

const (
	Lock          Type = "lock"
	LostMode      Type = "lost_mode"
	LostModeEnd   Type = "lost_mode_end"
	ClearPasscode Type = "clear_passcode"
	WipeSelective Type = "wipe_selective"
	WipeFull      Type = "wipe_full"
)

type State string

const (
	Held         State = "held"
	Approved     State = "approved"
	Queued       State = "queued"
	Pushed       State = "pushed"
	Acknowledged State = "acknowledged"
	Expired      State = "expired"
	Refused      State = "refused"
)

// NonceTTL is R4's thirty minutes.
const NonceTTL = 30 * time.Minute

var (
	ErrUnknownType    = errors.New("command: unknown type")
	ErrNotPermitted   = errors.New("command: this role may not do that")
	ErrLimiterTripped = errors.New("command: bulk-wipe limiter tripped, queue paused")
	ErrWrongState     = errors.New("command: command is not in a state that allows this")
	ErrBadNonce       = errors.New("command: one-time code does not match")
	ErrNonceUsed      = errors.New("command: one-time code has already been used")
	ErrNonceExpired   = errors.New("command: one-time code has expired")
	ErrNoDevice       = errors.New("command: no such device in this tenant")
)

// Spec is what a command type costs. Reversible actions need one decision;
// the one irreversible action needs two, from two different roles.
type Spec struct {
	Reversible bool
	Approvals  int
	Needs      authz.Action
}

var specs = map[Type]Spec{
	Lock:          {Reversible: true, Approvals: 1, Needs: authz.LockDevice},
	LostMode:      {Reversible: true, Approvals: 1, Needs: authz.LockDevice},
	LostModeEnd:   {Reversible: true, Approvals: 1, Needs: authz.LockDevice},
	ClearPasscode: {Reversible: true, Approvals: 1, Needs: authz.LockDevice},
	WipeSelective: {Reversible: true, Approvals: 1, Needs: authz.RequestWipe},
	WipeFull:      {Reversible: false, Approvals: 2, Needs: authz.RequestWipe},
}

func SpecFor(t Type) (Spec, bool) { s, ok := specs[t]; return s, ok }

// Types returns every type, so a test can assert that exactly one is
// irreversible and that it is the only one needing two approvals.
func Types() []Type {
	return []Type{Lock, LostMode, LostModeEnd, ClearPasscode, WipeSelective, WipeFull}
}

type Command struct {
	ID              uuid.UUID
	DeviceID        uuid.UUID
	Type            Type
	State           State
	Reversible      bool
	ApprovalsNeeded int
	RequestedBy     string
	RequestedByRole string
	Reason          string
	Signature       string
	Nonce           string
	NonceExpiresAt  *time.Time
	RequestedAt     time.Time
	AcknowledgedAt  *time.Time
	RefusedReason   string
}

// Limiter is R1. The specification's threshold is more than ten full wipes by
// one admin in sixty minutes.
type Limiter struct {
	MaxFullWipes int
	Window       time.Duration
}

func DefaultLimiter() Limiter { return Limiter{MaxFullWipes: 10, Window: time.Hour} }

type Pipeline struct {
	keys    KeyProvider
	push    PushProvider
	limiter Limiter
	now     func() time.Time
	// OnWiped runs when a wipe is DONE: acknowledged by the device, or
	// carried out by the vendor. Offboarding retires the device there,
	// and not a moment before, because a certificate revoked before the
	// wipe lands is a wipe that never lands.
	OnWiped func(ctx context.Context, tx *data.Tx, c Command) error
	// OnPushed runs when a command has been pushed towards a device. The
	// gateway wakes the device's long-poll with it, which is what makes
	// a lock land in seconds rather than at the next check-in (F12).
	//
	// It runs inside the command's transaction, so a wake that has to be
	// ordered after the commit (a database notification) can be raised on
	// the transaction itself and delivered by PostgreSQL at commit.
	OnPushed func(ctx context.Context, tx *data.Tx, deviceID uuid.UUID)
}

// Keys is the signing key provider, for the device route that hands out
// the public halves.
func (p *Pipeline) Keys() KeyProvider { return p.keys }

func (p *Pipeline) wiped(ctx context.Context, tx *data.Tx, c Command) error {
	if p.OnWiped == nil || (c.Type != WipeSelective && c.Type != WipeFull) {
		return nil
	}
	return p.OnWiped(ctx, tx, c)
}

func New(keys KeyProvider, push PushProvider, limiter Limiter) *Pipeline {
	return &Pipeline{keys: keys, push: push, limiter: limiter, now: time.Now}
}

// SetClock is for tests that need to stand at a particular moment. Production
// never calls it.
func (p *Pipeline) SetClock(f func() time.Time) { p.now = f }

type RequestInput struct {
	DeviceID uuid.UUID
	Type     Type
	Reason   string
	// Offboarding says this wipe is the work-data removal of an
	// offboarding, asked for by a caller holding offboard.employee rather
	// than wipe.request. It permits WipeSelective only: an HR feed may
	// say a person has left, and that is all it may cause.
	Offboarding bool
}

// Request creates a command. A reversible type with one approval is approved
// and signed by the asking; the irreversible one is held until a second,
// different person with a different role agrees.
func (p *Pipeline) Request(ctx context.Context, tx *data.Tx, in RequestInput) (Command, error) {
	spec, ok := specs[in.Type]
	if !ok {
		return Command{}, fmt.Errorf("%w: %q", ErrUnknownType, in.Type)
	}

	claim := tx.Claim()
	role := authz.Role(claim.Role)
	permitted := authz.Can(role, spec.Needs)
	if in.Offboarding && in.Type == WipeSelective && authz.Can(role, authz.OffboardEmployee) {
		permitted = true
	}
	if !permitted {
		return Command{}, fmt.Errorf("%w: %s may not %s", ErrNotPermitted, role, spec.Needs)
	}
	if in.Reason == "" {
		return Command{}, errors.New("command: a reason is required and is shown to the approver")
	}

	// The device must exist in this tenant. Row-level security already makes
	// another tenant's device invisible, so this check cannot be fooled into
	// confirming one exists elsewhere.
	var exists bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM devices WHERE id = $1)`, in.DeviceID).Scan(&exists); err != nil {
		return Command{}, err
	}
	if !exists {
		return Command{}, ErrNoDevice
	}

	// R1. Counted from the commands table rather than a separate tally, so
	// there is one source of truth and it survives a restart.
	if in.Type == WipeFull {
		tripped, err := p.limiterTripped(ctx, tx, claim.Subject)
		if err != nil {
			return Command{}, err
		}
		if tripped {
			// The attempt is still recorded. A refusal is kept as carefully
			// as a permitted action, and this one is also the alert.
			c, rerr := p.insert(ctx, tx, in, spec, Refused,
				"bulk-wipe limiter: more than "+fmt.Sprint(p.limiter.MaxFullWipes)+
					" full wipes by this admin inside the window")
			if rerr != nil {
				return Command{}, rerr
			}
			_ = data.AppendAudit(ctx, tx, "command.refused.limiter", c.ID.String())
			return c, ErrLimiterTripped
		}
	}

	// Always inserted held. Signing comes next, and only a signed command is
	// moved to approved, because the schema refuses an approved command with
	// no signature and that ordering is the thing being protected.
	c, err := p.insert(ctx, tx, in, spec, Held, "")
	if err != nil {
		return Command{}, err
	}
	if spec.Approvals == 1 {
		if c, err = p.sign(ctx, tx, c); err != nil {
			return Command{}, err
		}
		if c, err = p.setState(ctx, tx, c.ID, Approved); err != nil {
			return Command{}, err
		}
	}
	_ = data.AppendAudit(ctx, tx, "command."+string(in.Type)+".requested", c.ID.String())
	return c, nil
}

func (p *Pipeline) limiterTripped(ctx context.Context, tx *data.Tx, admin string) (bool, error) {
	var n int
	err := tx.QueryRow(ctx, `
		SELECT count(*) FROM commands
		 WHERE requested_by = $1
		   AND type = 'wipe_full'
		   AND state <> 'refused'
		   AND requested_at > $2`,
		admin, p.now().Add(-p.limiter.Window)).Scan(&n)
	return n >= p.limiter.MaxFullWipes, err
}

func (p *Pipeline) insert(ctx context.Context, tx *data.Tx, in RequestInput,
	spec Spec, state State, refusedReason string) (Command, error) {

	claim := tx.Claim()
	var refusedAt *time.Time
	var reason *string
	if state == Refused {
		t := p.now()
		refusedAt, reason = &t, &refusedReason
	}

	var c Command
	err := tx.QueryRow(ctx, `
		INSERT INTO commands (tenant_id, device_id, type, state, reversible,
		                      approvals_required, requested_by, requested_by_role,
		                      reason, refused_at, refused_reason)
		VALUES (app.current_tenant(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, device_id, type, state, reversible, approvals_required,
		          requested_by, requested_by_role, reason, requested_at,
		          coalesce(refused_reason,'')`,
		in.DeviceID, string(in.Type), string(state), spec.Reversible, spec.Approvals,
		claim.Subject, claim.Role, in.Reason, refusedAt, reason).
		Scan(&c.ID, &c.DeviceID, &c.Type, &c.State, &c.Reversible, &c.ApprovalsNeeded,
			&c.RequestedBy, &c.RequestedByRole, &c.Reason, &c.RequestedAt, &c.RefusedReason)
	return c, err
}

type DecisionInput struct {
	Approve bool
	Note    string
}

// Decide records one person's answer. The database enforces that it is not
// the requester and that two approvals carry two different roles, so a new
// handler cannot forget either rule.
func (p *Pipeline) Decide(ctx context.Context, tx *data.Tx, id uuid.UUID,
	in DecisionInput) (Command, error) {

	claim := tx.Claim()
	role := authz.Role(claim.Role)
	if !authz.Can(role, authz.ApproveWipe) {
		return Command{}, fmt.Errorf("%w: %s may not approve", ErrNotPermitted, role)
	}

	c, err := p.load(ctx, tx, id)
	if err != nil {
		return Command{}, err
	}
	if c.State != Held {
		return Command{}, fmt.Errorf("%w: %s is %s, not held", ErrWrongState, id, c.State)
	}

	decision := "refused"
	if in.Approve {
		decision = "approved"
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO command_approvals (tenant_id, command_id, approver, approver_role, decision, note)
		VALUES (app.current_tenant(), $1, $2, $3, $4, $5)`,
		id, claim.Subject, claim.Role, decision, in.Note); err != nil {
		return Command{}, err
	}

	if !in.Approve {
		if _, err := tx.Exec(ctx, `
			UPDATE commands SET state='refused', refused_at=now(),
			       refused_reason=$2 WHERE id=$1`,
			id, "refused by "+claim.Subject); err != nil {
			return Command{}, err
		}
		_ = data.AppendAudit(ctx, tx, "command.refused", id.String())
		return p.load(ctx, tx, id)
	}

	var approvals int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM command_approvals
		 WHERE command_id = $1 AND decision = 'approved'`, id).Scan(&approvals); err != nil {
		return Command{}, err
	}
	// The request itself is the first approval for a one-approval type; a
	// two-approval type needs the requester plus this one.
	if approvals+1 < c.ApprovalsNeeded {
		_ = data.AppendAudit(ctx, tx, "command.approved.partial", id.String())
		return p.load(ctx, tx, id)
	}

	// Sign first, then move the state. The reverse order is refused by the
	// schema, which is how this was caught.
	if c, err = p.sign(ctx, tx, c); err != nil {
		return Command{}, err
	}
	if c, err = p.setState(ctx, tx, id, Approved); err != nil {
		return Command{}, err
	}
	_ = data.AppendAudit(ctx, tx, "command.approved", id.String())
	return c, nil
}

func (p *Pipeline) load(ctx context.Context, tx *data.Tx, id uuid.UUID) (Command, error) {
	var c Command
	err := tx.QueryRow(ctx, `
		SELECT id, device_id, type, state, reversible, approvals_required,
		       requested_by, requested_by_role, reason, coalesce(signature,''),
		       coalesce(nonce,''), nonce_expires_at, requested_at,
		       acknowledged_at, coalesce(refused_reason,'')
		  FROM commands WHERE id = $1`, id).
		Scan(&c.ID, &c.DeviceID, &c.Type, &c.State, &c.Reversible, &c.ApprovalsNeeded,
			&c.RequestedBy, &c.RequestedByRole, &c.Reason, &c.Signature,
			&c.Nonce, &c.NonceExpiresAt, &c.RequestedAt, &c.AcknowledgedAt, &c.RefusedReason)
	return c, err
}

func (p *Pipeline) setState(ctx context.Context, tx *data.Tx, id uuid.UUID, st State) (Command, error) {
	if _, err := tx.Exec(ctx, `UPDATE commands SET state=$2 WHERE id=$1`, id, string(st)); err != nil {
		return Command{}, err
	}
	return p.load(ctx, tx, id)
}

// Filter narrows a listing. Everything it returns is already tenant-scoped by
// the transaction, so there is no tenant field here to get wrong.
type Filter struct {
	DeviceID uuid.UUID
	OnlyHeld bool
	Limit    int
}

// List is what the console's approvals queue and a device's history both read.
func List(ctx context.Context, tx *data.Tx, f Filter) ([]Command, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	rows, err := tx.Query(ctx, `
		SELECT id, device_id, type, state, reversible, approvals_required,
		       requested_by, requested_by_role, reason, coalesce(signature,''),
		       coalesce(nonce,''), nonce_expires_at, requested_at,
		       acknowledged_at, coalesce(refused_reason,'')
		  FROM commands
		 WHERE ($1::uuid IS NULL OR device_id = $1)
		   AND ($2 = false OR state = 'held')
		 ORDER BY requested_at DESC
		 LIMIT $3`, nullUUID(f.DeviceID), f.OnlyHeld, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Command{}
	for rows.Next() {
		var c Command
		if err := rows.Scan(&c.ID, &c.DeviceID, &c.Type, &c.State, &c.Reversible,
			&c.ApprovalsNeeded, &c.RequestedBy, &c.RequestedByRole, &c.Reason,
			&c.Signature, &c.Nonce, &c.NonceExpiresAt, &c.RequestedAt,
			&c.AcknowledgedAt, &c.RefusedReason); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func nullUUID(u uuid.UUID) *uuid.UUID {
	if u == uuid.Nil {
		return nil
	}
	return &u
}

// Load is List for one command. Returns pgx.ErrNoRows for a command in
// another tenant, which the handlers turn into 404 rather than 403.
func Load(ctx context.Context, tx *data.Tx, id uuid.UUID) (Command, error) {
	p := &Pipeline{now: time.Now}
	return p.load(ctx, tx, id)
}

// Done is the only state the console reports as finished.
func (c Command) Done() bool { return c.State == Acknowledged }

// NeedsADecision is what puts a command in the approvals queue.
func (c Command) NeedsADecision() bool { return c.State == Held }

// Label is how a command type reads to a person rather than to a database.
func (c Command) Label() string {
	switch c.Type {
	case Lock:
		return "Lock the device"
	case LostMode:
		return "Put in Lost Mode"
	case LostModeEnd:
		return "End Lost Mode"
	case ClearPasscode:
		return "Clear the passcode"
	case WipeSelective:
		return "Remove work data"
	case WipeFull:
		return "Erase everything"
	}
	return string(c.Type)
}
