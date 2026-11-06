// Package data is the only way into the database.
//
// The shape of this package is the control. The connection pool is
// unexported and is never returned, so there is no path from application
// code to a query that has not first been given a verified tenant claim.
// That is what the specification means by "no application path that
// disables it": not a rule people follow, a type they cannot get around.
//
// The tenant is set with set_config(..., is_local => true), so it lives for
// the transaction and not the connection. Connections are pooled and reused;
// a session-scoped setting would leak one tenant's context into the next
// request to borrow that connection. There is a test for exactly that.
package data

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"platform/internal/tenantclaim"
)

var ErrNoTenant = errors.New("data: no verified tenant claim, refusing to query")

// Store owns the pool. Nothing else may.
type Store struct {
	pool      *pgxpool.Pool
	signer    *tenantclaim.Signer
	rateCalls atomic.Int64
}

func Open(ctx context.Context, dsn string, signer *tenantclaim.Signer, maxConns int32) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	if maxConns > 0 {
		cfg.MaxConns = maxConns
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool: pool, signer: signer}, nil
}

func (s *Store) Close() { s.pool.Close() }

// Tx is a transaction that already has a tenant set on it. Every repository
// function takes one of these, which is why none of them takes a tenant id:
// there is no opportunity for a caller to pass the wrong one.
type Tx struct {
	tx    pgx.Tx
	claim tenantclaim.Claim
}

func (t *Tx) Claim() tenantclaim.Claim { return t.claim }

func (t *Tx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return t.tx.Query(ctx, sql, args...)
}

func (t *Tx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return t.tx.QueryRow(ctx, sql, args...)
}

func (t *Tx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return t.tx.Exec(ctx, sql, args...)
}

// WithTenant verifies the token, opens a transaction, sets the tenant on it,
// and runs fn. A token that does not verify never reaches a transaction, so a
// failed verification costs a connection nothing.
//
// token comes from the signed internal claim on the request. It never comes
// from a field a user can type. The database cannot enforce that; this
// function is where it is enforced, and it is the single piece of code in the
// platform most worth reviewing.
func (s *Store) WithTenant(ctx context.Context, token string, fn func(context.Context, *Tx) error) error {
	if token == "" {
		return ErrNoTenant
	}
	claim, err := s.signer.Verify(token)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNoTenant, err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// is_local => true. Transaction-scoped, so it is gone when this returns
	// and the connection goes back to the pool carrying nothing. The role,
	// subject and email go with the tenant (0042), so the database can hold
	// an employee to their own devices whatever the SQL asks for.
	if _, err := tx.Exec(ctx,
		`SELECT set_config('app.tenant_id', $1, true),
		        set_config('app.role', $2, true),
		        set_config('app.subject', $3, true),
		        set_config('app.email', $4, true)`,
		claim.TenantID.String(), claim.Role, claim.Subject, claim.Email); err != nil {
		return err
	}

	if err := fn(ctx, &Tx{tx: tx, claim: claim}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// operatorPool is deliberately absent. Operator-scoped reads that legitimately
// cross tenants (billing aggregates, the tenant list) belong in their own
// package with their own role and their own audit trail, and that package has
// no access to device, policy or key tables. Adding a "just this once" escape
// hatch here is how the isolation model dies.

// ---------------------------------------------------------------- wake

// Notify raises a database notification on this transaction. PostgreSQL
// delivers it when the transaction commits and never if it rolls back,
// which is exactly the order a wake needs: nobody is told to look for a
// command that is not there yet.
func (t *Tx) Notify(ctx context.Context, channel, payload string) error {
	if err := checkChannel(channel); err != nil {
		return err
	}
	_, err := t.tx.Exec(ctx, `SELECT pg_notify($1, $2)`, channel, payload)
	return err
}

// Listen holds one connection open on a channel and hands every payload to
// fn until ctx ends. The connection is the pool's, taken out of rotation
// for the duration; after an error it is given back and another is taken
// a moment later, so a restarted database costs a short gap, not the
// feature. Payloads are text raised by this platform's own transactions and
// are treated as data by whoever receives them.
func (s *Store) Listen(ctx context.Context, channel string, fn func(payload string)) error {
	if err := checkChannel(channel); err != nil {
		return err
	}
	for {
		err := s.listenOnce(ctx, channel, fn)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_ = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func (s *Store) listenOnce(ctx context.Context, channel string, fn func(string)) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "LISTEN "+channel); err != nil {
		return err
	}
	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		fn(n.Payload)
	}
}

// checkChannel keeps a channel name to what can be spliced into LISTEN
// safely: letters, digits and underscores, nothing a quote could reach.
func checkChannel(name string) error {
	if name == "" || len(name) > 63 {
		return errors.New("data: a notification channel name is 1 to 63 characters")
	}
	for _, r := range name {
		if !(r == '_' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			return errors.New("data: a notification channel name is lower-case letters, digits and underscores")
		}
	}
	return nil
}

// ---------------------------------------------------------------- rate

// TakeToken takes one token from a shared bucket, refilled at perMinute
// and holding at most a minute's worth. It is the one method on the store
// that runs without a tenant claim, deliberately: the table it reaches
// holds a key and a count and nothing of any tenant's, and the check runs
// at the door, before a claim exists. One statement, atomic on the row,
// so two instances taking at once cannot both see the last token.
func (s *Store) TakeToken(ctx context.Context, key string, perMinute int) (bool, error) {
	if n := s.rateCalls.Add(1); n%5000 == 0 {
		// Housekeeping on the way past: a bucket nobody has touched for a
		// day is a caller who went away. Not a scheduled job, because it
		// does not need to be one.
		_, _ = s.pool.Exec(ctx, `DELETE FROM api_rate WHERE last < now() - interval '1 day'`)
	}
	var ok bool
	err := s.pool.QueryRow(ctx, `
		INSERT INTO api_rate (key, tokens, last) VALUES ($1, $2::double precision - 1, now())
		ON CONFLICT (key) DO UPDATE SET
		  tokens = LEAST($2::double precision,
		                 api_rate.tokens + EXTRACT(EPOCH FROM (now() - api_rate.last)) * $2::double precision / 60.0) - 1,
		  last = now()
		WHERE LEAST($2::double precision,
		            api_rate.tokens + EXTRACT(EPOCH FROM (now() - api_rate.last)) * $2::double precision / 60.0) >= 1
		RETURNING true`, key, perMinute).Scan(&ok)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return ok, err
}
