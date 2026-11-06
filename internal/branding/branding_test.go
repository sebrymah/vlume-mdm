package branding

import (
	"errors"
	"math"
	"testing"
)

// The design document's commitment: accessibility is not something a tenant
// can switch off by choosing badly. A colour that would make white text
// unreadable is refused with the reason, not accepted and rendered.

func TestContrastAgainstKnownValues(t *testing.T) {
	// White on black is 21 to 1, white on white is 1 to 1. Anything that gets
	// these wrong has the luminance formula wrong.
	for _, c := range []struct {
		hex  string
		want float64
	}{
		{"#000000", 21.0},
		{"#FFFFFF", 1.0},
		{"#767676", 4.54}, // the canonical borderline grey
	} {
		got, err := ContrastWithWhite(c.hex)
		if err != nil {
			t.Fatalf("%s: %v", c.hex, err)
		}
		if math.Abs(got-c.want) > 0.05 {
			t.Errorf("%s: got %.2f, want about %.2f", c.hex, got, c.want)
		}
	}
}

func TestReadableColoursAreAccepted(t *testing.T) {
	for _, hex := range []string{
		"#0F6E66", // the demonstration tenant's teal
		"#9A4A12", // a rust a second tenant might pick
		"#1A1A18",
		"#3C4FB8",
		"#036", // three digit form
	} {
		if err := Validate(hex); err != nil {
			t.Errorf("%s was refused: %v", hex, err)
		}
	}
}

func TestUnreadableColoursAreRefusedWithTheReason(t *testing.T) {
	for _, hex := range []string{
		"#FFFF00", // yellow: white text on it is about 1.07 to 1
		"#FFFFFF",
		"#CCCCCC",
		"#7CFC00",
	} {
		err := Validate(hex)
		if err == nil {
			t.Errorf("%s was accepted, and white text on it cannot be read", hex)
			continue
		}
		if !errors.Is(err, ErrContrast) {
			t.Errorf("%s: refused for the wrong reason: %v", hex, err)
		}
		// The message has to name the number and the requirement, so a tenant
		// is told what is wrong rather than that something is wrong.
		if len(err.Error()) < 40 {
			t.Errorf("%s: refusal is too terse to act on: %q", hex, err)
		}
	}
}

func TestMalformedColoursAreRefused(t *testing.T) {
	for _, hex := range []string{"", "#12345", "not-a-colour", "#GGGGGG", "rgb(1,2,3)"} {
		if err := Validate(hex); err == nil {
			t.Errorf("%q was accepted as a colour", hex)
		}
	}
}

func TestPlaceholderIsRecognised(t *testing.T) {
	if !Default().IsPlaceholder() {
		t.Fatal("the default brand is not recognised as a placeholder")
	}
	if !(Brand{ProductName: "  "}).IsPlaceholder() {
		t.Fatal("an empty product name is not recognised as a placeholder")
	}
	if (Brand{ProductName: "Kalesi Device Care"}).IsPlaceholder() {
		t.Fatal("a real product name is being treated as a placeholder")
	}
}

// The neutral default must name no operator and no product, because a tenant
// that has not branded itself still shows this to its own staff.
func TestTheDefaultBrandNamesNobody(t *testing.T) {
	d := Default()
	if d.LegalFooter != "" {
		t.Errorf("the default carries a legal footer: %q", d.LegalFooter)
	}
	if d.ProductName != Placeholder {
		t.Errorf("the default product name is %q, not the placeholder", d.ProductName)
	}
}
