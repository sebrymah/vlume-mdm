package gateway

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"platform/internal/data"
)

// F12: a lock delivered in seconds.
//
// The agent long-polls its own queue: GET /api/my/commands?wait=50 holds
// the connection until there is something to do, the wait runs out, or
// the gateway is told that a command was pushed to this device. The
// instruction still travels over the device's own authenticated
// connection; the wake is only timing. A device that is not listening
// gets it at its next check-in, as before.
//
// The registry is per instance; the wake is not. A push raises a database
// notification on the command's own transaction, PostgreSQL delivers it at
// commit to every instance listening (RunWake), and each wakes the polls it
// holds. So a lock requested on one gateway reaches a phone held open on
// another in the time a notification takes, and the fallback tick is what
// it says: a fallback, for an instance whose listener is between
// connections.

const (
	maxWait      = 55 * time.Second
	fallbackPoll = 5 * time.Second
)

type waiters struct {
	mu sync.Mutex
	by map[uuid.UUID][]chan struct{}
}

func newWaiters() *waiters { return &waiters{by: map[uuid.UUID][]chan struct{}{}} }

func (w *waiters) add(id uuid.UUID) chan struct{} {
	ch := make(chan struct{}, 1)
	w.mu.Lock()
	w.by[id] = append(w.by[id], ch)
	w.mu.Unlock()
	return ch
}

func (w *waiters) remove(id uuid.UUID, ch chan struct{}) {
	w.mu.Lock()
	defer w.mu.Unlock()
	list := w.by[id]
	for i, c := range list {
		if c == ch {
			w.by[id] = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(w.by[id]) == 0 {
		delete(w.by, id)
	}
}

// wake tells every poll held for this device to look again.
func (w *waiters) wake(id uuid.UUID) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, ch := range w.by[id] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// await blocks until woken, until the fallback tick, or until wait runs
// out. It returns true when the caller should look again.
func (w *waiters) await(ctx context.Context, id uuid.UUID, wait time.Duration) bool {
	ch := w.add(id)
	defer w.remove(id, ch)
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	tick := time.NewTimer(fallbackPoll)
	defer tick.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-deadline.C:
		return false
	case <-tick.C:
		return true
	case <-ch:
		return true
	}
}

// wakeChannel is the one notification channel the platform uses. The
// payload is a device id and nothing else: it says "look at your queue",
// and what the device then reads is under its own tenant's row-level
// security like every other read.
const wakeChannel = "mdm_wake"

// pushed is the pipeline's OnPushed: this instance's polls now, every
// instance's polls at commit.
func (g *Gateway) pushed(ctx context.Context, tx *data.Tx, id uuid.UUID) {
	g.waiters.wake(id)
	if err := tx.Notify(ctx, wakeChannel, id.String()); err != nil {
		g.log.Warn("shared wake not raised; the fallback tick will carry it", "device", id, "err", err)
	}
}

// RunWake listens for wakes raised by every instance, this one included,
// and wakes the polls held here. It runs for the life of the process.
func (g *Gateway) RunWake(ctx context.Context) {
	g.log.Info("shared wake listening", "channel", wakeChannel)
	_ = g.store.Listen(ctx, wakeChannel, func(payload string) {
		if id, err := uuid.Parse(payload); err == nil {
			g.waiters.wake(id)
		}
	})
}
