// Package notify tells someone.
//
// It exists because the platform had started claiming it already did. When
// the bulk-wipe limiter trips, the console says "your queue is paused and
// the Security Manager has been told", and nothing told anyone. A product
// that says a control fired when it did not is worse than one without the
// control, because the person reading that line stops looking.
//
// THE OUTBOX. A notification is written in the same transaction as the event
// that caused it, and delivered afterwards. Enqueue takes the caller's
// transaction for exactly that reason, and there is no function here that
// sends anything inline. The three properties this buys:
//
//	nothing is lost      the row commits with the event or neither does
//	nothing is blocked   a wipe request does not fail because chat is down
//	nothing is invented  there is no message without its event
//
// Calling a webhook inline fails all three. A slow endpoint holds the
// request open, a failing one either loses the message or rolls back a
// legitimate wipe, and a retry after commit can tell someone about an event
// that was then rolled back.
//
// WHAT IT DOES NOT DO. It does not resolve people. Sending to "everyone who
// may approve a wipe" would mean holding a directory of a tenant's staff and
// their roles, and this platform holds neither: people live at the tenant's
// own identity provider. A tenant points a topic at a channel their team
// already watches.
package notify

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"platform/internal/branding"
	"platform/internal/data"
	"platform/internal/secrets"
)

// Topic is the fixed catalogue, for the same reason the policy rules are a
// fixed catalogue: a tenant can point a topic somewhere, and cannot invent
// one that nothing ever raises.
type Topic string

const (
	// DeviceLost is the eleven-o'clock-at-night one. Somebody's laptop is
	// gone and the person who knows cannot reach the help desk.
	DeviceLost Topic = "device.lost"
	// ApprovalWaiting is a command held for a second person. Without it,
	// dual approval degrades into a queue nobody looks at.
	ApprovalWaiting Topic = "approval.waiting"
	// LimiterTripped is R1. This is the one the product was already
	// claiming to send.
	LimiterTripped Topic = "limiter.tripped"
	DeviceWiped    Topic = "device.wiped"
	EnrolmentDone  Topic = "enrolment.completed"
	// CertificateExpiring is the one nobody asks for and everybody needs.
	// A device whose certificate runs out stops authenticating on a
	// particular day, and a device that has gone silent looks exactly like
	// a stolen one until somebody checks.
	CertificateExpiring Topic = "certificate.expiring"
	// DeviceQuarantined is F9 acting: a policy asked for quarantine on
	// failure and a device failed.
	DeviceQuarantined Topic = "device.quarantined"
	// EnforcementHalted is F9 declining to act: too much of the fleet is
	// failing at once for an automatic quarantine to be the right move.
	EnforcementHalted Topic = "enforcement.halted"
	// DeviceReleased is a person letting a quarantined device back in. The
	// network listens to this one and to DeviceQuarantined; the access
	// feed is the source of truth between them.
	DeviceReleased Topic = "device.released"
	// ReportCompliance is F18's scheduled half: the weekly summary and a
	// link to the download.
	ReportCompliance Topic = "report.compliance"
	// QuotaReached is the plan saying no: a device could not be added.
	QuotaReached Topic = "quota.reached"
	// SIEMAudit is F19: every audit event, as a stream to the tenant's
	// SIEM. Set its target to a syslog:// or syslogs:// destination, or a
	// webhook. The exporter in internal/siem keeps the cursor.
	SIEMAudit Topic = "siem.audit"
)

func Topics() []Topic {
	return []Topic{DeviceLost, ApprovalWaiting, LimiterTripped, DeviceWiped,
		EnrolmentDone, CertificateExpiring, DeviceQuarantined, EnforcementHalted, DeviceReleased,
		ReportCompliance, QuotaReached, SIEMAudit}
}

func (t Topic) Valid() bool {
	for _, k := range Topics() {
		if k == t {
			return true
		}
	}
	return false
}

// Describe is what the settings page shows beside each topic, so an
// administrator choosing where to point it knows what will arrive.
func (t Topic) Describe() string {
	switch t {
	case DeviceLost:
		return "someone reports a device they hold as lost"
	case ApprovalWaiting:
		return "a command is waiting for a second person to approve it"
	case LimiterTripped:
		return "the bulk-wipe limiter pauses a queue"
	case DeviceWiped:
		return "a wipe is acknowledged by the device"
	case EnrolmentDone:
		return "a new device finishes enrolling"
	case CertificateExpiring:
		return "a device's certificate is running out and it has not renewed"
	case DeviceQuarantined:
		return "a policy quarantines a device that failed it"
	case EnforcementHalted:
		return "automatic quarantine stops because too much of the fleet is failing at once"
	case DeviceReleased:
		return "a person releases a quarantined device"
	case ReportCompliance:
		return "the weekly compliance summary, with a link to the full report"
	case QuotaReached:
		return "a device could not be added because the plan's cap is reached"
	case SIEMAudit:
		return "every audit event, streamed to your SIEM (syslog://host:port, syslogs:// for TLS, ?format=leef)"
	default:
		return string(t)
	}
}

const (
	// MaxAttempts before a notification is given up on. Five attempts over
	// the backoff below is roughly half an hour, which is long enough to
	// ride out a chat outage and short enough that a permanently wrong
	// endpoint surfaces the same morning.
	MaxAttempts = 5
	// FirstRetry doubles each attempt.
	FirstRetry = 30 * time.Second
)

var (
	ErrBadTopic    = errors.New("notify: unknown topic")
	ErrNoTarget    = errors.New("notify: nothing is listening for this topic")
	ErrBadEndpoint = errors.New("notify: that endpoint cannot be used")
)

// Message is one thing to tell someone. Rendered at enqueue time rather than
// at send time, so it describes the world as it was when the event happened
// rather than as it is when the channel comes back up.
type Message struct {
	Topic     Topic
	Subject   string
	Body      string
	ObjectRef string
	// DedupeKey stops the same event queuing twice while it is still
	// waiting. Pressing "report lost" five times is one message.
	DedupeKey string
	// Once says this key is announced at most once, ever, rather than once
	// per pending message.
	//
	// The difference matters for anything on a timer. DedupeKey alone
	// deduplicates only while a message is still WAITING: once it has been
	// delivered, its row is no longer pending and the next enqueue of the
	// same key succeeds. That is right for a button somebody presses twice
	// and wrong for a daily sweep, which would otherwise send the same
	// message about the same device every day for six weeks.
	//
	// The key has to carry whatever makes an occurrence distinct. The
	// expiry sweep puts the expiry date in its key, so a device that
	// renews and later approaches a NEW expiry is announced again.
	Once   bool
	Tenant string
	// Colour and Footer are the tenant's brand, for the HTML half of an
	// email: the band at the top and the legal line at the bottom. Stamp
	// fills them from the tenant's branding row.
	Colour string
	Footer string
	// Sender is the tenant's own verified sending identity, when they have
	// one. It carries a private key, so it exists for the length of one
	// delivery and is never stored on anything long-lived.
	Sender *SenderIdentity
}

// Channel is where a message goes. The port exists so the delivery mechanism
// is swappable without anything above it changing, which is the same rule
// the push provider and the key vault follow.
type Channel interface {
	Name() string
	Deliver(ctx context.Context, endpoint string, m Message) error
}

// ---------------------------------------------------------------- enqueue

// Enqueue records a notification inside the caller's transaction.
//
// It deliberately does NOT check whether a target exists. A tenant that has
// not configured a destination yet still produces the record, so the fact
// that an event happened and reached nobody is visible afterwards rather
// than silently absent. The worker marks it undeliverable with that reason.
func Enqueue(ctx context.Context, tx *data.Tx, m Message) error {
	if !m.Topic.Valid() {
		return fmt.Errorf("%w: %q", ErrBadTopic, m.Topic)
	}
	if strings.TrimSpace(m.Subject) == "" {
		return errors.New("notify: a notification with no subject tells nobody anything")
	}
	if m.DedupeKey == "" {
		m.DedupeKey = string(m.Topic) + ":" + m.ObjectRef
	}
	if m.Once {
		// Any row with this key, in any state, means it has been
		// announced. Including a failed one: a message that could not be
		// delivered is recorded and visible, and raising it again every
		// day would not make it more deliverable.
		//
		// Row-level security scopes the NOT EXISTS to this tenant, so one
		// tenant's announcement cannot suppress another's.
		_, err := tx.Exec(ctx, `
			INSERT INTO notifications
			  (tenant_id, topic, subject, body, object_ref, dedupe_key)
			SELECT app.current_tenant(), $1, $2, $3, $4, $5
			 WHERE NOT EXISTS (
			   SELECT 1 FROM notifications WHERE dedupe_key = $5)`,
			string(m.Topic), m.Subject, m.Body, m.ObjectRef, m.DedupeKey)
		return err
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO notifications
		  (tenant_id, topic, subject, body, object_ref, dedupe_key)
		VALUES (app.current_tenant(), $1, $2, $3, $4, $5)
		ON CONFLICT DO NOTHING`,
		string(m.Topic), m.Subject, m.Body, m.ObjectRef, m.DedupeKey)
	return err
}

// ---------------------------------------------------------------- targets

type Target struct {
	Topic     Topic
	Kind      string
	Endpoint  string
	CreatedBy string
	CreatedAt time.Time
}

// Redacted is what a settings page shows. A chat webhook URL is a
// credential, so the page proves one is configured without printing it back
// to anyone who can read the page.
//
// An email address is NOT a credential and is shown in full: hiding it would
// stop an administrator noticing that notifications have been going to
// somebody who left, which is the thing most worth noticing on that page.
func (t Target) Redacted() string {
	if t.Kind == "log" {
		return "written to this platform's own log"
	}
	if t.Kind == "jira" || t.Kind == "servicenow" {
		// The endpoint is JSON with a token in it; show the instance only.
		if c, err := ParseTicketConfig(t.Kind, t.Endpoint); err == nil {
			return t.Kind + " at " + c.URL
		}
		return t.Kind + " (configured)"
	}
	if t.Kind == "email" {
		return t.Endpoint
	}
	if len(t.Endpoint) <= 28 {
		return "configured"
	}
	return t.Endpoint[:24] + "…" + t.Endpoint[len(t.Endpoint)-4:]
}

type Service struct {
	sealer   secrets.Sealer
	channels map[string]Channel
	// CoalesceAbove: this many messages of one topic waiting together go
	// out as one digest. Zero means DefaultCoalesceAbove.
	CoalesceAbove int
	Now           func() time.Time
	// LookupTXT is how a sending domain is proven. A field so a test can
	// answer it, and so a deployment behind a split-horizon resolver can
	// point it at something that sees the public internet.
	LookupTXT LookupTXT
}

func New(sealer secrets.Sealer, channels ...Channel) *Service {
	s := &Service{sealer: sealer, channels: map[string]Channel{},
		Now: func() time.Time { return time.Now().UTC() }}
	for _, c := range channels {
		s.channels[c.Name()] = c
	}
	return s
}

// SetTarget points a topic somewhere.
func (s *Service) SetTarget(ctx context.Context, tx *data.Tx, topic Topic,
	kind, endpoint, by string) error {

	if !topic.Valid() {
		return fmt.Errorf("%w: %q", ErrBadTopic, topic)
	}
	if _, ok := s.channels[kind]; !ok {
		return fmt.Errorf("%w: this deployment has no %q channel", ErrBadEndpoint, kind)
	}
	switch kind {
	case "webhook":
		if err := checkWebhook(endpoint); err != nil {
			return err
		}
	case "email":
		// Parsed at SAVE time, so somebody who mistypes an address is told
		// on the form rather than by a delivery that failed an hour later.
		// It is also where a header-injection attempt is refused, at the
		// moment it is typed.
		if _, err := ParseRecipients(endpoint); err != nil {
			return fmt.Errorf("%w: %v", ErrBadEndpoint, err)
		}
	case "syslog":
		if err := checkSyslog(endpoint); err != nil {
			return err
		}
	case "jira", "servicenow":
		if _, err := ParseTicketConfig(kind, endpoint); err != nil {
			return err
		}
	}
	sealed, err := s.sealer.Seal(ctx, tx, []byte(endpoint))
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO notification_targets
		  (tenant_id, topic, kind, endpoint_sealed, created_by)
		VALUES (app.current_tenant(), $1, $2, $3, $4)
		ON CONFLICT (tenant_id, topic) DO UPDATE SET
		  kind = excluded.kind, endpoint_sealed = excluded.endpoint_sealed,
		  created_by = excluded.created_by, created_at = now()`,
		string(topic), kind, sealed, by); err != nil {
		return err
	}
	return data.AppendAudit(ctx, tx, "notification.target_set", string(topic))
}

func (s *Service) ClearTarget(ctx context.Context, tx *data.Tx, topic Topic) error {
	tag, err := tx.Exec(ctx,
		`DELETE FROM notification_targets WHERE topic = $1`, string(topic))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoTarget
	}
	return data.AppendAudit(ctx, tx, "notification.target_cleared", string(topic))
}

func (s *Service) Targets(ctx context.Context, tx *data.Tx) ([]Target, error) {
	rows, err := tx.Query(ctx, `
		SELECT topic, kind, endpoint_sealed, created_by, created_at
		  FROM notification_targets ORDER BY topic`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Target{}
	for rows.Next() {
		var (
			t      Target
			topic  string
			sealed []byte
		)
		if err := rows.Scan(&topic, &t.Kind, &sealed, &t.CreatedBy, &t.CreatedAt); err != nil {
			return nil, err
		}
		t.Topic = Topic(topic)
		if open, err := s.sealer.Open(ctx, tx, sealed); err == nil {
			t.Endpoint = string(open)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Service) target(ctx context.Context, tx *data.Tx, topic Topic) (Target, error) {
	var (
		t      Target
		sealed []byte
	)
	err := tx.QueryRow(ctx, `
		SELECT kind, endpoint_sealed FROM notification_targets WHERE topic = $1`,
		string(topic)).Scan(&t.Kind, &sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return Target{}, ErrNoTarget
	}
	if err != nil {
		return Target{}, err
	}
	open, err := s.sealer.Open(ctx, tx, sealed)
	if err != nil {
		return Target{}, fmt.Errorf("notify: the stored endpoint cannot be opened: %w", err)
	}
	t.Topic = topic
	t.Endpoint = string(open)
	return t, nil
}

// ---------------------------------------------------------------- draining

type Pending struct {
	ID        uuid.UUID
	Topic     Topic
	Subject   string
	Body      string
	ObjectRef string
	Attempts  int
}

// Drain delivers what is waiting for ONE tenant, inside that tenant's own
// transaction.
//
// SKIP LOCKED matters: with more than one gateway running, each takes a
// different row rather than queueing behind the same one, and a row being
// delivered by one instance is invisible to the others. Without it, a second
// instance would either block or send a duplicate.
func (s *Service) Drain(ctx context.Context, tx *data.Tx, limit int) (sent, failed int, err error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := tx.Query(ctx, `
		SELECT id, topic, subject, body, object_ref, attempts
		  FROM notifications
		 WHERE state = 'pending' AND next_attempt_at <= $1
		 ORDER BY created_at
		 LIMIT $2
		 FOR UPDATE SKIP LOCKED`, s.Now(), limit)
	if err != nil {
		return 0, 0, err
	}
	var batch []Pending
	for rows.Next() {
		var p Pending
		var topic string
		if err := rows.Scan(&p.ID, &topic, &p.Subject, &p.Body, &p.ObjectRef,
			&p.Attempts); err != nil {
			rows.Close()
			return 0, 0, err
		}
		p.Topic = Topic(topic)
		batch = append(batch, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}

	// Coalescing. Many devices failing at once is one event to the person
	// reading the channel, not twelve; a topic with several messages
	// waiting goes out as one digest that lists them all. Below the line
	// they go one by one, as they always did.
	byTopic := map[Topic][]Pending{}
	var order []Topic
	for _, p := range batch {
		if _, seen := byTopic[p.Topic]; !seen {
			order = append(order, p.Topic)
		}
		byTopic[p.Topic] = append(byTopic[p.Topic], p)
	}
	for _, topic := range order {
		group := byTopic[topic]
		if len(group) >= s.coalesceAbove() {
			done, derr := s.deliverDigest(ctx, tx, topic, group)
			if derr != nil {
				failed += len(group)
				continue
			}
			if done {
				sent += len(group)
				continue
			}
			// No target: each row settles as undeliverable below.
		}
		for _, p := range group {
			if derr := s.deliverOne(ctx, tx, p); derr != nil {
				failed++
				continue
			}
			sent++
		}
	}
	return sent, failed, nil
}

// DefaultCoalesceAbove is how many messages of one topic, waiting
// together, become one digest.
const DefaultCoalesceAbove = 3

func (s *Service) coalesceAbove() int {
	if s.CoalesceAbove > 0 {
		return s.CoalesceAbove
	}
	return DefaultCoalesceAbove
}

// deliverDigest sends one message for a group of the same topic. It says
// whether it delivered (false with no error means there is no target and
// the rows are the caller's to settle one by one).
func (s *Service) deliverDigest(ctx context.Context, tx *data.Tx, topic Topic, group []Pending) (bool, error) {
	target, err := s.target(ctx, tx, topic)
	if errors.Is(err, ErrNoTarget) {
		return false, nil
	}
	if err != nil {
		for _, p := range group {
			_ = s.retryOrGiveUp(ctx, tx, p, err)
		}
		return false, err
	}
	channel, ok := s.channels[target.Kind]
	if !ok {
		return false, nil
	}
	var body strings.Builder
	fmt.Fprintf(&body, "%d of these arrived together, so they are sent as one.\n\n", len(group))
	for _, p := range group {
		fmt.Fprintf(&body, "- %s", p.Subject)
		if p.ObjectRef != "" {
			fmt.Fprintf(&body, " (%s)", p.ObjectRef)
		}
		body.WriteString("\n")
	}
	m := Message{
		Topic:     topic,
		Subject:   fmt.Sprintf("%d at once: %s", len(group), topic.Describe()),
		Body:      body.String(),
		ObjectRef: fmt.Sprintf("digest:%s:%d", topic, len(group)),
	}
	if serr := s.Stamp(ctx, tx, &m); serr != nil {
		for _, p := range group {
			_ = s.settle(ctx, tx, p, "failed", serr.Error())
		}
		return false, serr
	}
	if derr := channel.Deliver(ctx, target.Endpoint, m); derr != nil {
		for _, p := range group {
			_ = s.retryOrGiveUp(ctx, tx, p, derr)
		}
		return false, derr
	}
	for _, p := range group {
		if _, err := tx.Exec(ctx, `
			UPDATE notifications SET state = 'sent', sent_at = $2, attempts = attempts + 1, last_error = $3
			 WHERE id = $1`, p.ID, s.Now(), fmt.Sprintf("sent as one of %d", len(group))); err != nil {
			return false, err
		}
		if err := data.AppendAudit(ctx, tx, "notification.sent",
			fmt.Sprintf("%s %s (as one of %d)", p.Topic, p.ObjectRef, len(group))); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (s *Service) deliverOne(ctx context.Context, tx *data.Tx, p Pending) error {
	target, err := s.target(ctx, tx, p.Topic)
	if errors.Is(err, ErrNoTarget) {
		// Not a failure to retry. Nothing is listening and nothing will
		// start listening because we tried again. Mark it so, with the
		// reason, because the point of recording it at all is that an
		// event reaching nobody should be visible.
		return s.settle(ctx, tx, p, "undeliverable",
			"no destination is configured for "+string(p.Topic))
	}
	if err != nil {
		return s.retryOrGiveUp(ctx, tx, p, err)
	}

	channel, ok := s.channels[target.Kind]
	if !ok {
		return s.settle(ctx, tx, p, "undeliverable",
			"this deployment has no "+target.Kind+" channel")
	}

	m := Message{Topic: p.Topic, Subject: p.Subject, Body: p.Body, ObjectRef: p.ObjectRef}
	if serr := s.Stamp(ctx, tx, &m); serr != nil {
		// Worth settling rather than retrying: a key that cannot be opened
		// will not open on the next attempt either.
		return s.settle(ctx, tx, p, "failed", serr.Error())
	}
	if derr := channel.Deliver(ctx, target.Endpoint, m); derr != nil {
		return s.retryOrGiveUp(ctx, tx, p, derr)
	}

	if _, err := tx.Exec(ctx, `
		UPDATE notifications SET state = 'sent', sent_at = $2, attempts = attempts + 1
		 WHERE id = $1`, p.ID, s.Now()); err != nil {
		return err
	}
	// Audited, so "were they told" is answerable from the tenant's own
	// record rather than from a log nobody keeps.
	return data.AppendAudit(ctx, tx, "notification.sent",
		string(p.Topic)+" "+p.ObjectRef)
}

func (s *Service) retryOrGiveUp(ctx context.Context, tx *data.Tx, p Pending, cause error) error {
	if p.Attempts+1 >= MaxAttempts {
		return s.settle(ctx, tx, p, "failed", cause.Error())
	}
	// Doubling. A fleet of gateways hammering a recovering endpoint every
	// thirty seconds is a second outage caused by the first.
	wait := FirstRetry * time.Duration(1<<p.Attempts)
	_, err := tx.Exec(ctx, `
		UPDATE notifications
		   SET attempts = attempts + 1, last_error = $2, next_attempt_at = $3
		 WHERE id = $1`, p.ID, cause.Error(), s.Now().Add(wait))
	if err != nil {
		return err
	}
	return cause
}

func (s *Service) settle(ctx context.Context, tx *data.Tx, p Pending, state, why string) error {
	if _, err := tx.Exec(ctx, `
		UPDATE notifications SET state = $2, last_error = $3, attempts = attempts + 1
		 WHERE id = $1`, p.ID, state, why); err != nil {
		return err
	}
	// The failure is audited too. A notification that could not be
	// delivered is part of the record of what the platform did and did not
	// tell anyone, and an operator who believes they were told when they
	// were not is the worst outcome this package has.
	if err := data.AppendAudit(ctx, tx, "notification."+state,
		string(p.Topic)+" "+p.ObjectRef+": "+why); err != nil {
		return err
	}
	return errors.New(why)
}

// Recent is what the settings page shows: what has been sent, and more
// usefully what has not.
func Recent(ctx context.Context, tx *data.Tx, limit int) ([]Record, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := tx.Query(ctx, `
		SELECT topic, subject, state, attempts, coalesce(last_error,''),
		       created_at, sent_at
		  FROM notifications ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Record{}
	for rows.Next() {
		var r Record
		if err := rows.Scan(&r.Topic, &r.Subject, &r.State, &r.Attempts,
			&r.LastError, &r.CreatedAt, &r.SentAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type Record struct {
	Topic     string
	Subject   string
	State     string
	Attempts  int
	LastError string
	CreatedAt time.Time
	SentAt    *time.Time
}

func (r Record) Delivered() bool { return r.State == "sent" }

// Stamp puts the tenant on a message: its product name and, when a domain
// of theirs is verified, its own sending identity. The outbox does this to
// every message; a caller that mails somebody directly (an enrolment
// invitation) does the same, so no email leaves without the tenant's name
// on it. An email landing in a person's inbox is as tenant-facing as a
// page in the console, and T12 applies to both.
func (s *Service) Stamp(ctx context.Context, tx *data.Tx, m *Message) error {
	if b, err := branding.Load(ctx, tx); err == nil && !b.IsPlaceholder() {
		m.Tenant = b.ProductName
		m.Colour, m.Footer = b.Colour, b.LegalFooter
	}
	// identity() returns nothing for an unverified domain, so a domain
	// nobody proved cannot become a From address.
	id, err := s.identity(ctx, tx)
	if err != nil {
		return err
	}
	m.Sender = id
	return nil
}

// TargetFor is the target for one topic, opened, for a caller that
// delivers directly rather than through the outbox.
func (s *Service) TargetFor(ctx context.Context, tx *data.Tx, topic Topic) (Target, error) {
	return s.target(ctx, tx, topic)
}

// DeliverNow hands one message to a target's channel, outside the outbox.
// The SIEM stream uses it: a stream keeps its own position and must know
// whether THIS event was taken before it moves on, which the outbox's
// retry-later cannot tell it.
func (s *Service) DeliverNow(ctx context.Context, target Target, m Message) error {
	channel, ok := s.channels[target.Kind]
	if !ok {
		return fmt.Errorf("%w: this deployment has no %q channel", ErrBadEndpoint, target.Kind)
	}
	return channel.Deliver(ctx, target.Endpoint, m)
}
