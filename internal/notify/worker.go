package notify

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"platform/internal/data"
	"platform/internal/tenantclaim"
)

// Worker drains the outbox.
//
// It walks tenants and drains each one inside that tenant's own
// transaction, rather than reading the whole table with a cross-tenant
// connection. That costs a query per tenant per tick and it keeps the
// isolation model exactly as it was: there is still only one place in this
// platform that reads across tenants, and it is the directory.
//
// The claim it mints names a subject that is obviously not a person, so the
// audit entries this produces read as the platform's own work rather than as
// somebody's.
type Worker struct {
	svc    *Service
	store  *data.Store
	signer *tenantclaim.Signer
	// Tenants is passed in rather than taken from the directory package, so
	// this package depends on nothing that reads across tenants.
	Tenants func(ctx context.Context) ([]uuid.UUID, error)
	Every   time.Duration
	Batch   int
	log     *slog.Logger
}

func NewWorker(svc *Service, store *data.Store, signer *tenantclaim.Signer,
	tenants func(context.Context) ([]uuid.UUID, error), log *slog.Logger) *Worker {
	return &Worker{
		svc: svc, store: store, signer: signer, Tenants: tenants,
		Every: 20 * time.Second, Batch: 20, log: log,
	}
}

// Once drains every tenant and returns what it managed.
//
// A tenant whose drain fails does not stop the others: one tenant with a
// broken endpoint must not hold up everybody else's notifications, which is
// the multi-tenant version of not letting one bad row stop a queue.
func (w *Worker) Once(ctx context.Context) (sent, failed int) {
	tenants, err := w.Tenants(ctx)
	if err != nil {
		w.log.Error("notifier: could not list tenants", "err", err)
		return 0, 0
	}
	for _, id := range tenants {
		s, f, err := w.drainOne(ctx, id)
		if err != nil {
			w.log.Error("notifier: drain failed", "tenant", id, "err", err)
			continue
		}
		sent += s
		failed += f
	}
	return sent, failed
}

func (w *Worker) drainOne(ctx context.Context, tenant uuid.UUID) (int, int, error) {
	claim, err := w.signer.Mint(tenantclaim.Claim{
		TenantID: tenant, Subject: "system:notifier",
		Role: "platform_operator", RequestID: uuid.NewString(),
	}, 2*time.Minute)
	if err != nil {
		return 0, 0, err
	}
	var sent, failed int
	err = w.store.WithTenant(ctx, claim, func(ctx context.Context, tx *data.Tx) error {
		var derr error
		sent, failed, derr = w.svc.Drain(ctx, tx, w.Batch)
		return derr
	})
	return sent, failed, err
}

func (w *Worker) Run(ctx context.Context) {
	if w.Every <= 0 {
		w.Every = 20 * time.Second
	}
	w.log.Info("notifier running", "every", w.Every)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(w.Every):
		}
		if sent, failed := w.Once(ctx); sent > 0 || failed > 0 {
			w.log.Info("notifier", "sent", sent, "failed", failed)
		}
	}
}
