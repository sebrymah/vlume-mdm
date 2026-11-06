package command

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"platform/internal/data"
)

// PushProvider wakes a device. It is the whole of the Apple, Google and
// Microsoft dependency in this package: everything above it is built and
// tested, and this one interface is where the vendor programmes land.
//
// The specification's portability rule in one sentence: changing provider
// means replacing an adapter, not domain logic.
type PushProvider interface {
	Name() string
	Push(ctx context.Context, t PushTarget) error
}

type PushTarget struct {
	OSFamily string
	Token    string
	Topic    string
	// DeviceID and Type are for a channel that does the work itself
	// rather than waking an agent: Android Enterprise issues the command
	// through Google and nothing on the device acknowledges it to us.
	DeviceID uuid.UUID
	Type     Type
	// Tx is the caller's transaction, for a channel that needs to read
	// the device's vendor name. Nil for a channel that does not.
	Tx *data.Tx
}

// Executor is a PushProvider that carries the command out itself. Dispatch
// marks such a command acknowledged rather than pushed: there is no agent
// on the far side to say it ran, and the vendor has already said so.
type Executor interface {
	PushProvider
	Executes(osFamily string) bool
}

// ByOS routes each operating system to its own channel. Anything not
// listed goes to the fallback, which for Apple is still NotConfigured.
type ByOS struct {
	Routes   map[string]PushProvider
	Fallback PushProvider
}

func (b ByOS) Name() string { return "by operating system" }

func (b ByOS) provider(os string) PushProvider {
	if p, ok := b.Routes[os]; ok {
		return p
	}
	return b.Fallback
}

func (b ByOS) Push(ctx context.Context, t PushTarget) error {
	return b.provider(t.OSFamily).Push(ctx, t)
}

func (b ByOS) Executes(os string) bool {
	e, ok := b.provider(os).(Executor)
	return ok && e.Executes(os)
}

var ErrPushNotConfigured = errors.New("command: push is not configured")

// NotConfigured is the honest stand-in for a provider we cannot build yet.
// It names what is missing rather than failing vaguely, so a queued command
// that is going nowhere says why on the screen.
type NotConfigured struct {
	Provider string
	Missing  string
}

func (n NotConfigured) Name() string { return n.Provider }

func (n NotConfigured) Push(context.Context, PushTarget) error {
	return fmt.Errorf("%w: %s needs %s", ErrPushNotConfigured, n.Provider, n.Missing)
}

// AppleNotConfigured is what the platform ships with today.
func AppleNotConfigured() NotConfigured {
	return NotConfigured{
		Provider: "Apple Push Notification service",
		Missing: "the Apple MDM vendor CSR signing certificate, and then a per-tenant " +
			"APNs push certificate created under that tenant's own Apple ID",
	}
}

// Dispatch moves an approved command towards the device.
//
// A command that cannot be pushed because we have no provider stays queued.
// It is not refused: the command is fine and the tenant did nothing wrong.
// The gap is ours, and a queue that holds its work until the gap closes is
// the correct behaviour.
func (p *Pipeline) Dispatch(ctx context.Context, tx *data.Tx, id uuid.UUID) (Command, error) {
	c, err := p.load(ctx, tx, id)
	if err != nil {
		return Command{}, err
	}
	if c.State != Approved && c.State != Queued {
		return c, fmt.Errorf("%w: %s is %s", ErrWrongState, id, c.State)
	}
	if c.NonceExpiresAt != nil && p.now().After(*c.NonceExpiresAt) {
		return p.expire(ctx, tx, id)
	}

	if c.State == Approved {
		if _, err := tx.Exec(ctx,
			`UPDATE commands SET state='queued', queued_at=now() WHERE id=$1`, id); err != nil {
			return Command{}, err
		}
	}

	target := PushTarget{DeviceID: c.DeviceID, Type: c.Type, Tx: tx}
	if err := tx.QueryRow(ctx,
		`SELECT os_family FROM devices WHERE id=$1`, c.DeviceID).Scan(&target.OSFamily); err != nil {
		return Command{}, err
	}

	if err := p.push.Push(ctx, target); err != nil {
		// Stays queued. Deliberately not an audit failure either: the
		// platform not being finished is not an event in the tenant's
		// security record. The agent's own long-poll is still woken: the
		// instruction travels over that connection, and a push is only
		// ever the wake-up for a device that is not already listening.
		if p.OnPushed != nil {
			p.OnPushed(ctx, tx, c.DeviceID)
		}
		return p.load(ctx, tx, id)
	}

	if e, ok := p.push.(Executor); ok && e.Executes(target.OSFamily) {
		// The vendor ran it. Done, with the one-time code spent so the
		// path an agent would take to acknowledge it is closed.
		if _, err := tx.Exec(ctx, `
			UPDATE commands SET state='acknowledged', pushed_at=now(), acknowledged_at=now(),
			       nonce_used_at=now() WHERE id=$1`, id); err != nil {
			return Command{}, err
		}
		_ = data.AppendAudit(ctx, tx, "command.executed_by_vendor", id.String()+" via:"+p.push.Name())
		done, err := p.load(ctx, tx, id)
		if err != nil {
			return Command{}, err
		}
		return done, p.wiped(ctx, tx, done)
	}

	if _, err := tx.Exec(ctx,
		`UPDATE commands SET state='pushed', pushed_at=now() WHERE id=$1`, id); err != nil {
		return Command{}, err
	}
	// Pushed, not done. A wake-up was sent; nothing has run yet.
	_ = data.AppendAudit(ctx, tx, "command.pushed", id.String())
	if p.OnPushed != nil {
		p.OnPushed(ctx, tx, c.DeviceID)
	}
	return p.load(ctx, tx, id)
}

// Acknowledge is the device saying it ran the command. This is the only state
// the console reports as done.
//
// The one-time code is checked three ways: it must match, it must not have
// been used, and it must not have expired. A replay is refused and recorded.
func (p *Pipeline) Acknowledge(ctx context.Context, tx *data.Tx, id uuid.UUID, nonce string) (Command, error) {
	c, err := p.load(ctx, tx, id)
	if err != nil {
		return Command{}, err
	}
	if c.State != Queued && c.State != Pushed {
		return c, fmt.Errorf("%w: %s is %s", ErrWrongState, id, c.State)
	}
	if c.Nonce == "" || nonce != c.Nonce {
		_ = data.AppendAudit(ctx, tx, "command.ack.rejected.bad_code", id.String())
		return c, ErrBadNonce
	}

	var usedAt *string
	if err := tx.QueryRow(ctx,
		`SELECT nonce_used_at::text FROM commands WHERE id=$1`, id).Scan(&usedAt); err != nil {
		return Command{}, err
	}
	if usedAt != nil {
		_ = data.AppendAudit(ctx, tx, "command.ack.rejected.replay", id.String())
		return c, ErrNonceUsed
	}
	if c.NonceExpiresAt != nil && p.now().After(*c.NonceExpiresAt) {
		out, eerr := p.expire(ctx, tx, id)
		if eerr != nil {
			return Command{}, eerr
		}
		return out, ErrNonceExpired
	}

	if _, err := tx.Exec(ctx, `
		UPDATE commands SET state='acknowledged', acknowledged_at=now(),
		       nonce_used_at=now() WHERE id=$1`, id); err != nil {
		return Command{}, err
	}
	_ = data.AppendAudit(ctx, tx, "command."+string(c.Type)+".acknowledged", id.String())
	done, err := p.load(ctx, tx, id)
	if err != nil {
		return Command{}, err
	}
	return done, p.wiped(ctx, tx, done)
}

// expire marks a command dead. It is never re-signed and never retried: a
// fresh request is a fresh decision, with fresh approvals.
func (p *Pipeline) expire(ctx context.Context, tx *data.Tx, id uuid.UUID) (Command, error) {
	if _, err := tx.Exec(ctx, `UPDATE commands SET state='expired' WHERE id=$1`, id); err != nil {
		return Command{}, err
	}
	_ = data.AppendAudit(ctx, tx, "command.expired", id.String())
	return p.load(ctx, tx, id)
}

// ExpireOverdue is the sweep. Anything signed whose code has run out stops
// being deliverable, so a command cannot sit in a queue for a week and then
// land on a device whose owner has long since been told it failed.
func (p *Pipeline) ExpireOverdue(ctx context.Context, tx *data.Tx) (int, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE commands SET state='expired'
		 WHERE state IN ('approved','queued','pushed')
		   AND nonce_expires_at IS NOT NULL
		   AND nonce_expires_at < $1`, p.now())
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}
