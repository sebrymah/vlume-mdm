package data

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The people the platform has met (0040). Not a directory: a row appears
// when a person signs in, when an administrator assigns a device to an
// address, or when HR says someone has left. It stays when they leave, so
// their devices stay theirs and the next hire with the same address starts
// with none.

type Person struct {
	ID        uuid.UUID
	Subject   string
	Email     string
	Name      string
	Source    string
	FirstSeen time.Time
	LastSeen  time.Time
	LeftAt    *time.Time
	LeftBy    string
	// Devices is how many devices the person holds that are not retired,
	// on the listing.
	Devices int
}

// Left says whether HR, or an administrator, has said this person has
// gone.
func (p Person) Left() bool { return p.LeftAt != nil }

// Label is how the person is shown: their name, else their address, else
// the provider's subject.
func (p Person) Label() string {
	switch {
	case p.Name != "":
		return p.Name
	case p.Email != "":
		return p.Email
	}
	return p.Subject
}

var ErrNoSuchPerson = errors.New("data: no such person")

// activePerson is the one clause that says who a subject or an address
// belongs to NOW: the row with that subject, or, for a person who has not
// signed in yet, the row with that address that nobody has left. A leaver's
// row matches nothing, which is the whole point of keeping it. The control
// --break-emailreuse lets a leaver's row match again.
const activePerson = `left_at IS NULL
		   AND ( ($1 <> '' AND subject = $1)
		      OR ($2 <> '' AND email = lower($2)) )`

func scanPerson(row pgx.Row, p *Person) error {
	return row.Scan(&p.ID, &p.Subject, &p.Email, &p.Name, &p.Source,
		&p.FirstSeen, &p.LastSeen, &p.LeftAt, &p.LeftBy)
}

const personColumns = `id, subject, email, name, source, first_seen, last_seen, left_at, coalesce(left_by,'')`

// SeenAtSignIn records that a person is in front of us, with what the
// provider said about them. The subject is the identifier a provider never
// reuses, so it is the key: a row with it is this person, whatever the
// address now is. A row with the address and no subject yet is a person an
// administrator assigned a device to before they first signed in, and it
// becomes theirs. Anyone else with that address and a different subject
// has, as far as the provider is concerned, lost it: the address moves,
// with an audit line, because the provider is the authority on addresses.
func SeenAtSignIn(ctx context.Context, tx *Tx, subject, email, name string, now time.Time) (Person, error) {
	subject = strings.TrimSpace(subject)
	email = strings.ToLower(strings.TrimSpace(email))
	name = strings.TrimSpace(name)
	if subject == "" {
		return Person{}, errors.New("data: a sign-in without a subject cannot be a person")
	}
	// The address, if another active row holds it, moves here.
	if email != "" {
		var other uuid.UUID
		err := tx.QueryRow(ctx, `
			SELECT id FROM people WHERE left_at IS NULL AND email = $1 AND subject <> '' AND subject <> $2`,
			email, subject).Scan(&other)
		if err == nil {
			if _, err := tx.Exec(ctx, `UPDATE people SET email = '' WHERE id = $1`, other); err != nil {
				return Person{}, err
			}
			if err := AppendAudit(ctx, tx, "person.email_moved",
				"email:"+email+" from:"+other.String()+" to_subject:"+subject); err != nil {
				return Person{}, err
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return Person{}, err
		}
	}
	var p Person
	// By subject first: this person, whatever they are called now.
	err := scanPerson(tx.QueryRow(ctx, `
		UPDATE people SET email = CASE WHEN $2 <> '' THEN $2 ELSE email END,
		                  name = CASE WHEN $3 <> '' THEN $3 ELSE name END,
		                  last_seen = $4
		 WHERE left_at IS NULL AND subject = $1
		 RETURNING `+personColumns, subject, email, name, now), &p)
	if err == nil {
		return p, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Person{}, err
	}
	// Then the address, if it was assigned to before a sign-in.
	if email != "" {
		err = scanPerson(tx.QueryRow(ctx, `
			UPDATE people SET subject = $1, name = CASE WHEN $3 <> '' THEN $3 ELSE name END, last_seen = $4
			 WHERE left_at IS NULL AND subject = '' AND email = $2
			 RETURNING `+personColumns, subject, email, name, now), &p)
		if err == nil {
			return p, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return Person{}, err
		}
	}
	err = scanPerson(tx.QueryRow(ctx, `
		INSERT INTO people (tenant_id, subject, email, name, source, first_seen, last_seen)
		VALUES (app.current_tenant(), $1, $2, $3, 'sign_in', $4, $4)
		RETURNING `+personColumns, subject, email, name, now), &p)
	if err != nil {
		return Person{}, err
	}
	return p, AppendAudit(ctx, tx, "person.first_seen", "person:"+p.ID.String()+" subject:"+subject)
}

// PersonFor is who an administrator means when they type an address or a
// subject: the active person with it, or a new row for someone the
// platform has not met, so a device can be assigned to a person before
// their first sign-in. Empty means nobody.
func PersonFor(ctx context.Context, tx *Tx, typed string, now time.Time) (*uuid.UUID, error) {
	typed = strings.TrimSpace(typed)
	if typed == "" {
		return nil, nil
	}
	subject, email := typed, ""
	if strings.Contains(typed, "@") {
		subject, email = "", strings.ToLower(typed)
	}
	var id uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM people WHERE `+activePerson, subject, email).Scan(&id)
	if err == nil {
		return &id, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO people (tenant_id, subject, email, source, first_seen, last_seen)
		VALUES (app.current_tenant(), $1, $2, 'assignment', $3, $3) RETURNING id`,
		subject, email, now).Scan(&id)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

// MyPerson is the signed-in person's own row, if the platform has one.
func MyPerson(ctx context.Context, tx *Tx) (Person, bool, error) {
	subject, email, ok := tx.whoAmI()
	if !ok {
		return Person{}, false, nil
	}
	var p Person
	err := scanPerson(tx.QueryRow(ctx, `SELECT `+personColumns+` FROM people WHERE `+activePerson, subject, email), &p)
	if errors.Is(err, pgx.ErrNoRows) {
		return Person{}, false, nil
	}
	if err != nil {
		return Person{}, false, err
	}
	return p, true, nil
}

func GetPerson(ctx context.Context, tx *Tx, id uuid.UUID) (Person, error) {
	var p Person
	err := scanPerson(tx.QueryRow(ctx, `SELECT `+personColumns+` FROM people WHERE id = $1`, id), &p)
	if errors.Is(err, pgx.ErrNoRows) {
		return Person{}, ErrNoSuchPerson
	}
	return p, err
}

// FindPerson resolves what an administrator typed, without creating.
func FindPerson(ctx context.Context, tx *Tx, typed string) (Person, bool, error) {
	typed = strings.TrimSpace(typed)
	subject, email := typed, ""
	if strings.Contains(typed, "@") {
		subject, email = "", typed
	}
	var p Person
	err := scanPerson(tx.QueryRow(ctx, `SELECT `+personColumns+` FROM people WHERE `+activePerson, subject, email), &p)
	if errors.Is(err, pgx.ErrNoRows) {
		return Person{}, false, nil
	}
	if err != nil {
		return Person{}, false, err
	}
	return p, true, nil
}

// ListPeople is the page: everyone met, with how many devices each holds,
// narrowed by a search over name, address and subject.
func ListPeople(ctx context.Context, tx *Tx, query string) ([]Person, error) {
	q := "%" + strings.ToLower(strings.TrimSpace(query)) + "%"
	rows, err := tx.Query(ctx, `
		SELECT p.id, p.subject, p.email, p.name, p.source, p.first_seen, p.last_seen, p.left_at, coalesce(p.left_by,''),
		       (SELECT count(*) FROM devices d WHERE d.person_id = p.id AND d.state <> 'retired')
		  FROM people p
		 WHERE $1 = '%%' OR lower(p.name) LIKE $1 OR p.email LIKE $1 OR lower(p.subject) LIKE $1
		 ORDER BY p.left_at IS NOT NULL, lower(coalesce(nullif(p.name,''), nullif(p.email,''), p.subject))
		 LIMIT 500`, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Person{}
	for rows.Next() {
		var p Person
		if err := rows.Scan(&p.ID, &p.Subject, &p.Email, &p.Name, &p.Source, &p.FirstSeen, &p.LastSeen,
			&p.LeftAt, &p.LeftBy, &p.Devices); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// MarkLeft is HR, or an administrator, saying the person has gone. Their
// row stays, with who said so and why; their subject and address are free
// for the next person. Already-left is not an error: HR systems repeat
// themselves.
func MarkLeft(ctx context.Context, tx *Tx, id uuid.UUID, by, reason string, now time.Time) error {
	tag, err := tx.Exec(ctx, `
		UPDATE people SET left_at = $2, left_by = $3, left_reason = $4
		 WHERE id = $1 AND left_at IS NULL`, id, now, by, reason)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	return AppendAudit(ctx, tx, "person.left", "person:"+id.String()+" by:"+by)
}

// RecordLeaver is HR saying someone we never met has left: the row is
// made already left, so the page shows what HR said and nothing is
// assigned to them by accident later.
func RecordLeaver(ctx context.Context, tx *Tx, typed, by, reason string, now time.Time) (uuid.UUID, error) {
	typed = strings.TrimSpace(typed)
	subject, email := typed, ""
	if strings.Contains(typed, "@") {
		subject, email = "", strings.ToLower(typed)
	}
	var id uuid.UUID
	// Said before: HR systems repeat themselves, and one leaver is one row.
	err := tx.QueryRow(ctx, `
		SELECT id FROM people WHERE left_at IS NOT NULL AND (($1 <> '' AND subject = $1) OR ($2 <> '' AND email = $2))
		 ORDER BY left_at DESC LIMIT 1`, subject, email).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, err
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO people (tenant_id, subject, email, source, first_seen, last_seen, left_at, left_by, left_reason)
		VALUES (app.current_tenant(), $1, $2, 'hr', $3, $3, $3, $4, $5) RETURNING id`,
		subject, email, now, by, reason).Scan(&id)
	return id, err
}

// DevicesOfPerson is everything the person holds that is not retired.
func DevicesOfPerson(ctx context.Context, tx *Tx, id uuid.UUID) ([]Device, error) {
	return devicesWhere(ctx, tx, `person_id = $1 AND state <> 'retired'`, id)
}

// PeopleLabels is every person by id as they are shown, for a report
// that names who holds each device without a query per row.
func PeopleLabels(ctx context.Context, tx *Tx) (map[uuid.UUID]string, error) {
	rows, err := tx.Query(ctx, `SELECT id, subject, email, name, left_at IS NOT NULL FROM people`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uuid.UUID]string{}
	for rows.Next() {
		var p Person
		var left bool
		if err := rows.Scan(&p.ID, &p.Subject, &p.Email, &p.Name, &left); err != nil {
			return nil, err
		}
		label := p.Label()
		if left {
			label += " (left)"
		}
		out[p.ID] = label
	}
	return out, rows.Err()
}
