// Package branding holds a tenant's own identity and the guard that stops a
// tenant choosing a colour nobody can read.
//
// Requirement T4: product name, logo, colour and legal footer in the console,
// the agents, the enrolment pages and the reports. Requirement T12: no
// operator or product brand appears in any tenant-facing surface.
//
// The design document's rule: accessibility is not something a tenant can
// switch off by choosing badly. A colour that would fail text contrast is
// refused with the reason, rather than accepted and rendered unreadable.
package branding

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/mail"
	"strconv"
	"strings"

	"platform/internal/data"
)

// Placeholder is what a tenant starts with. Default templates use a neutral
// placeholder name that a tenant must replace before going live, so the
// console says so loudly rather than letting it ship.
const Placeholder = "[YOUR PRODUCT NAME]"

type Brand struct {
	ProductName string
	LegalFooter string
	Colour      string
	MarkLetter  string
	// Who a finder should call. Shown on a lost device's lock screen and
	// nowhere else; empty means the screen asks for the device to be
	// handed in without saying where.
	LostPhone string
	LostEmail string
	// Whether an image is held; the bytes are read on their own route.
	HasLogo    bool
	HasFavicon bool
}

func (b Brand) IsPlaceholder() bool {
	return strings.TrimSpace(b.ProductName) == Placeholder || strings.TrimSpace(b.ProductName) == ""
}

// Default is what a tenant sees before it has been through branding setup.
// Deliberately neutral: it names no operator and no product.
func Default() Brand {
	return Brand{
		ProductName: Placeholder,
		LegalFooter: "",
		Colour:      "#4A4A44",
		MarkLetter:  "?",
	}
}

// Load reads the tenant's brand. A tenant with no row gets the neutral
// default rather than an error, because a half-onboarded tenant should still
// be able to open the console and finish onboarding.
func Load(ctx context.Context, tx *data.Tx) (Brand, error) {
	b := Default()
	err := tx.QueryRow(ctx, `
		SELECT product_name, legal_footer, brand_colour, mark_letter,
		       lost_contact_phone, lost_contact_email, logo IS NOT NULL, favicon IS NOT NULL
		  FROM tenant_branding`).Scan(
		&b.ProductName, &b.LegalFooter, &b.Colour, &b.MarkLetter, &b.LostPhone, &b.LostEmail,
		&b.HasLogo, &b.HasFavicon)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return Default(), nil
		}
		return Default(), err
	}
	return b, nil
}

// ---------------------------------------------------------------- contrast

var ErrContrast = errors.New("branding: colour fails text contrast")

// MinContrast is WCAG 2.1 AA for normal-sized text.
const MinContrast = 4.5

// Validate refuses a colour that white text cannot be read against, because
// the brand colour is used as the background of the console's header and the
// primary button. The error names the ratio and the requirement, so a tenant
// is told what is wrong rather than that something is wrong.
func Validate(hex string) error {
	l, err := luminance(hex)
	if err != nil {
		return err
	}
	got := contrast(l, 1.0) // against white
	if got < MinContrast {
		return fmt.Errorf("%w: white text on %s is %.2f to 1, and %.1f to 1 is required",
			ErrContrast, hex, got, MinContrast)
	}
	return nil
}

// ContrastWithWhite is exported so the branding screen can show the number
// live while someone is choosing, rather than only on save.
func ContrastWithWhite(hex string) (float64, error) {
	l, err := luminance(hex)
	if err != nil {
		return 0, err
	}
	return contrast(l, 1.0), nil
}

func contrast(a, b float64) float64 {
	hi, lo := a, b
	if lo > hi {
		hi, lo = lo, hi
	}
	return (hi + 0.05) / (lo + 0.05)
}

func luminance(hex string) (float64, error) {
	h := strings.TrimPrefix(strings.TrimSpace(hex), "#")
	if len(h) == 3 {
		h = string([]byte{h[0], h[0], h[1], h[1], h[2], h[2]})
	}
	if len(h) != 6 {
		return 0, fmt.Errorf("branding: %q is not a six digit hex colour", hex)
	}
	var c [3]float64
	for i := 0; i < 3; i++ {
		v, err := strconv.ParseUint(h[i*2:i*2+2], 16, 8)
		if err != nil {
			return 0, fmt.Errorf("branding: %q is not a hex colour", hex)
		}
		s := float64(v) / 255.0
		if s <= 0.03928 {
			c[i] = s / 12.92
		} else {
			c[i] = math.Pow((s+0.055)/1.055, 2.4)
		}
	}
	return 0.2126*c[0] + 0.7152*c[1] + 0.0722*c[2], nil
}

// Save writes the tenant's brand, refusing a colour nobody can read.
//
// The contrast guard runs here, at the write, rather than only on the form:
// a brand that reaches the row has to be one the console can render, or
// the next page load fails accessibility for every member of staff at once.
func Save(ctx context.Context, tx *data.Tx, b Brand) error {
	b.ProductName = strings.TrimSpace(b.ProductName)
	if b.ProductName == "" || b.ProductName == Placeholder {
		return errors.New("branding: a product name is required")
	}
	if len(b.ProductName) > 60 {
		return errors.New("branding: the product name is too long to fit the header")
	}
	if b.MarkLetter == "" {
		b.MarkLetter = strings.ToUpper(b.ProductName[:1])
	}
	if len([]rune(b.MarkLetter)) != 1 {
		return errors.New("branding: the mark is one letter")
	}
	if b.Colour == "" {
		b.Colour = Default().Colour
	}
	if err := Validate(b.Colour); err != nil {
		return err
	}
	b.LostPhone, b.LostEmail = strings.TrimSpace(b.LostPhone), strings.TrimSpace(b.LostEmail)
	if err := checkLostContact(b.LostPhone, b.LostEmail); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO tenant_branding
		  (tenant_id, product_name, legal_footer, brand_colour, mark_letter,
		   lost_contact_phone, lost_contact_email)
		VALUES (app.current_tenant(), $1, $2, $3, $4, $5, $6)
		ON CONFLICT (tenant_id) DO UPDATE SET
		  product_name = excluded.product_name, legal_footer = excluded.legal_footer,
		  brand_colour = excluded.brand_colour, mark_letter = excluded.mark_letter,
		  lost_contact_phone = excluded.lost_contact_phone,
		  lost_contact_email = excluded.lost_contact_email`,
		b.ProductName, b.LegalFooter, b.Colour, b.MarkLetter, b.LostPhone, b.LostEmail); err != nil {
		return err
	}
	return data.AppendAudit(ctx, tx, "branding.saved", b.ProductName)
}

// checkLostContact refuses contact details a finder could not use. A
// number is digits with the usual punctuation; an address is one net/mail
// can parse, with no display name, because it is typed into a lock screen.
func checkLostContact(phone, email string) error {
	if phone != "" {
		digits := 0
		for _, r := range phone {
			switch {
			case r >= '0' && r <= '9':
				digits++
			case r == '+' || r == ' ' || r == '-' || r == '(' || r == ')':
			default:
				return errors.New("branding: the lost-device phone number has characters a finder cannot dial")
			}
		}
		if digits < 6 || digits > 15 {
			return errors.New("branding: the lost-device phone number is not a dialable length")
		}
	}
	if email != "" {
		a, err := mail.ParseAddress(email)
		if err != nil || a.Name != "" || a.Address != email {
			return errors.New("branding: the lost-device email is not a plain address")
		}
	}
	return nil
}

// ---------------------------------------------------------------- images

const (
	MaxLogoBytes    = 200 * 1024
	MaxFaviconBytes = 64 * 1024
)

// ImageType is what the bytes are, by sniffing, or "" for anything a
// browser would not show as an image. SVG is text and is sniffed by its
// root element; the rest by their magic bytes.
func ImageType(b []byte) string {
	switch {
	case len(b) >= 8 && string(b[:8]) == "\x89PNG\r\n\x1a\n":
		return "image/png"
	case len(b) >= 3 && b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF:
		return "image/jpeg"
	case len(b) >= 4 && b[0] == 0 && b[1] == 0 && b[2] == 1 && b[3] == 0:
		return "image/x-icon"
	case len(b) >= 6 && (string(b[:6]) == "GIF87a" || string(b[:6]) == "GIF89a"):
		return "image/gif"
	}
	head := strings.ToLower(string(b[:min(len(b), 512)]))
	if strings.Contains(head, "<svg") && !strings.Contains(head, "<script") {
		return "image/svg+xml"
	}
	return ""
}

// SaveImage stores the logo or the favicon. kind is "logo" or "favicon".
func SaveImage(ctx context.Context, tx *data.Tx, kind string, b []byte) error {
	var column, maxBytes = "logo", MaxLogoBytes
	if kind == "favicon" {
		column, maxBytes = "favicon", MaxFaviconBytes
	} else if kind != "logo" {
		return errors.New("branding: the image is a logo or a favicon")
	}
	if len(b) == 0 {
		return errors.New("branding: the file is empty")
	}
	if len(b) > maxBytes {
		return fmt.Errorf("branding: the %s is %d KB; the most a page will carry is %d KB", kind, len(b)/1024, maxBytes/1024)
	}
	typ := ImageType(b)
	if typ == "" {
		return fmt.Errorf("branding: the %s is not a PNG, JPEG, GIF, ICO or SVG", kind)
	}
	if kind == "favicon" && typ == "image/svg+xml" {
		// Browsers disagree about SVG favicons; refuse rather than show a
		// broken tab on half of them.
		return errors.New("branding: a favicon is a PNG or an ICO")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO tenant_branding (tenant_id, product_name, `+column+`, `+column+`_type)
		VALUES (app.current_tenant(), $3, $1, $2)
		ON CONFLICT (tenant_id) DO UPDATE SET `+column+` = $1, `+column+`_type = $2`,
		b, typ, Placeholder); err != nil {
		return err
	}
	return data.AppendAudit(ctx, tx, "branding."+kind+".saved", typ)
}

// RemoveImage clears one.
func RemoveImage(ctx context.Context, tx *data.Tx, kind string) error {
	if kind != "logo" && kind != "favicon" {
		return errors.New("branding: the image is a logo or a favicon")
	}
	if _, err := tx.Exec(ctx, `UPDATE tenant_branding SET `+kind+` = NULL, `+kind+`_type = NULL`); err != nil {
		return err
	}
	return data.AppendAudit(ctx, tx, "branding."+kind+".removed", "")
}

// Image reads one back, for the route that serves it.
func Image(ctx context.Context, tx *data.Tx, kind string) ([]byte, string, bool, error) {
	if kind != "logo" && kind != "favicon" {
		return nil, "", false, nil
	}
	var b []byte
	var typ *string
	err := tx.QueryRow(ctx, `SELECT `+kind+`, `+kind+`_type FROM tenant_branding`).Scan(&b, &typ)
	if err != nil || len(b) == 0 || typ == nil {
		if err != nil && !strings.Contains(err.Error(), "no rows") {
			return nil, "", false, err
		}
		return nil, "", false, nil
	}
	return b, *typ, true, nil
}
