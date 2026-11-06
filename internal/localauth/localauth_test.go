package localauth

import (
	"strings"
	"testing"
	"time"
)

func TestAPasswordHashesAndVerifiesAndAWrongOneDoesNot(t *testing.T) {
	h, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=47104,t=2,p=1$") {
		t.Fatalf("hash format: %s", h)
	}
	if err := Verify("correct horse battery staple", h); err != nil {
		t.Fatalf("the right password failed: %v", err)
	}
	if err := Verify("correct horse battery stapl", h); err != ErrWrongPassword {
		t.Fatalf("a wrong password: %v", err)
	}
	// Two hashes of the same password differ: the salt is per hash.
	h2, _ := Hash("correct horse battery staple")
	if h == h2 {
		t.Fatal("two hashes of one password are identical, so there is no salt")
	}
	// The stored password is not in the hash.
	if strings.Contains(h, "horse") {
		t.Fatal("the password is in the hash")
	}
}

func TestAHashThatAsksForTheMoonIsRefusedNotObeyed(t *testing.T) {
	for _, bad := range []string{
		"", "plaintext", "$argon2id$v=19$m=4194304,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNo",
		"$argon2id$v=19$m=47104,t=200,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNo",
		"$argon2i$v=19$m=47104,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNo",
		"$argon2id$v=19$m=47104,t=2,p=1$AA$AA",
	} {
		if err := Verify("x", bad); err != ErrBadHash {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	if err := Verify(strings.Repeat("a", MaxPasswordBytes+1), "$argon2id$v=19$m=47104,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNo"); err != ErrWrongPassword {
		t.Fatalf("an enormous password: %v", err)
	}
	if _, err := Hash(strings.Repeat("a", MaxPasswordBytes+1)); err == nil {
		t.Fatal("an enormous password was hashed")
	}
}

func TestAnUnknownAccountCostsAboutAsMuchAsAWrongPassword(t *testing.T) {
	h, _ := Hash("a perfectly fine passphrase")
	start := time.Now()
	_ = Verify("not the password at all", h)
	wrong := time.Since(start)
	start = time.Now()
	VerifyAbsent("not the password at all")
	absent := time.Since(start)
	// Within a factor of three either way; the point is that one is not
	// instant. A Verify that returned early would be well under a tenth.
	if absent < wrong/3 || absent > wrong*3 {
		t.Fatalf("absent %v, wrong %v: an unknown address is distinguishable by time", absent, wrong)
	}
}

func TestThePasswordPolicySaysWhy(t *testing.T) {
	for _, c := range []struct {
		pw    string
		avoid []string
		want  string
	}{
		{"short1!", nil, "at least 12"},
		{"", nil, "at least 12"},
		{"passwordpassword", nil, "first anyone tries"},
		{"aaaaaaaaaaaaaa", nil, "repeat or a run"},
		{"abcdefghijklmn", nil, "repeat or a run"},
		{"987654321098765", nil, ""}, // not a clean run: allowed by this rule
		{"kemi.adeleke-is-great-2026", []string{"kemi.adeleke@kalesi.example"}, "name, address"},
		{"Kalesi-Foods-forever-1", []string{"Kalesi Foods"}, "name, address"},
		{"blue-lamp-ferry-cloud", []string{"kemi@kalesi.example", "Kemi Adeleke", "Kalesi Foods"}, ""},
		{strings.Repeat("a1", 600), nil, "too long"},
	} {
		err := CheckPassword(c.pw, c.avoid...)
		switch {
		case c.want == "" && err != nil:
			t.Fatalf("%q was refused: %v", c.pw, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Fatalf("%q: got %v, want %q", c.pw, err, c.want)
		}
	}
}

// RFC 6238 appendix B: SHA-1, the secret "12345678901234567890", the
// published codes at the published times. The last six digits of the RFC's
// eight-digit values.
func TestTOTPMatchesTheRFCsPublishedCodes(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, c := range []struct {
		unix int64
		code string
	}{
		{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"},
		{1234567890, "005924"}, {2000000000, "279037"},
	} {
		if got := Code(secret, time.Unix(c.unix, 0)); got != c.code {
			t.Fatalf("at %d: %s, want %s", c.unix, got, c.code)
		}
	}
}

func TestACodeIsAcceptedForOneStepEitherSideAndNoFurther(t *testing.T) {
	secret, _ := NewSecret()
	now := time.Unix(1_800_000_000, 0)
	cur := Code(secret, now)
	if step, ok := Match(secret, cur, now); !ok || step != StepAt(now) {
		t.Fatalf("the current code: %v %v", step, ok)
	}
	if _, ok := Match(secret, Code(secret, now.Add(-TOTPStep)), now); !ok {
		t.Fatal("the previous step's code was refused")
	}
	if _, ok := Match(secret, Code(secret, now.Add(TOTPStep)), now); !ok {
		t.Fatal("the next step's code was refused")
	}
	if _, ok := Match(secret, Code(secret, now.Add(3*TOTPStep)), now); ok {
		t.Fatal("a code three steps away was accepted")
	}
	// Typed with a space, as phones show it.
	if _, ok := Match(secret, cur[:3]+" "+cur[3:], now); !ok {
		t.Fatal("a code typed with a space was refused")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if _, ok := Match(secret, bad, now); ok {
			t.Fatalf("%q was accepted", bad)
		}
	}
}

func TestTheURIAndTheQRCodeAreWhatAnAppReads(t *testing.T) {
	secret, _ := NewSecret()
	u := URI("Kalesi Device Care", "o.martins@kalesi.example", secret)
	for _, want := range []string{"otpauth://totp/", "Kalesi%20Device%20Care", "secret=" + SecretText(secret),
		"digits=6", "period=30", "algorithm=SHA1"} {
		if !strings.Contains(u, want) {
			t.Fatalf("uri lacks %q: %s", want, u)
		}
	}
	png, err := QRPNG(u)
	if err != nil || len(png) < 200 || string(png[1:4]) != "PNG" {
		t.Fatalf("qr: %d bytes, %v", len(png), err)
	}
}

func TestRecoveryCodesAreTenDistinctAndHashedTheSameWayTheyAreTyped(t *testing.T) {
	codes, hashes, err := NewRecoveryCodes()
	if err != nil || len(codes) != 10 || len(hashes) != 10 {
		t.Fatalf("%d %d %v", len(codes), len(hashes), err)
	}
	seen := map[string]bool{}
	for i, c := range codes {
		if len(c) != 11 || c[5] != '-' || seen[c] {
			t.Fatalf("code %d: %q", i, c)
		}
		seen[c] = true
		// Typed in capitals, without the dash, with spaces: the same hash.
		typed := strings.ToUpper(strings.ReplaceAll(c, "-", " "))
		if HashRecovery(typed) != hashes[i] {
			t.Fatalf("code %q typed as %q hashes differently", c, typed)
		}
		if strings.Contains(hashes[i], c[:5]) {
			t.Fatal("a code is in its hash")
		}
	}
	if !LooksLikeRecovery(codes[0]) || LooksLikeRecovery("123456") || LooksLikeRecovery("123 456") {
		t.Fatal("the box cannot tell a recovery code from a six-digit one")
	}
}
