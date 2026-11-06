package directory

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The shipped list is held to its own shape: thousands of entries, every
// one a lower-case domain with at least two labels, and none of them a
// public suffix, because refusing co.uk would refuse a country.
func TestTheShippedListIsLargeAndWellFormed(t *testing.T) {
	if n := FreeMailCount(); n < 30000 {
		t.Fatalf("the shipped list holds %d domains; the point of it is to be large", n)
	}
	valid := regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$`)
	public := []string{"com", "net", "org", "co.uk", "com.au", "co.jp", "de", "fr", "ng", "co.za", "io", "me"}
	sc := bufio.NewScanner(strings.NewReader(freeMailData))
	for sc.Scan() {
		d := sc.Text()
		if d == "" || strings.HasPrefix(d, "#") {
			continue
		}
		if !valid.MatchString(d) || d != strings.ToLower(d) || d != strings.TrimSpace(d) {
			t.Fatalf("entry %q is not a lower-case domain", d)
		}
		for _, p := range public {
			if d == p {
				t.Fatalf("the list holds the public suffix %q", d)
			}
		}
	}
}

func TestTheObviousAndTheObscureAreRefused(t *testing.T) {
	for _, d := range []string{
		// The old short list.
		"gmail.com", "googlemail.com", "yahoo.co.uk", "hotmail.com", "outlook.com", "icloud.com", "proton.me",
		// Big in one country and missing from a short list.
		"yahoo.co.jp", "web.de", "mail.ru", "qq.com", "163.com", "naver.com", "rediffmail.com",
		"seznam.cz", "wp.pl", "libero.it", "orange.fr", "uol.com.br", "yandex.kz",
		// Disposable.
		"yopmail.com", "mailinator.com", "guerrillamail.com", "10minutemail.com", "temp-mail.org", "sharklasers.com",
	} {
		if !IsFreeMail(d) {
			t.Fatalf("%s was not refused", d)
		}
		if _, _, err := WorkEmail("someone@" + d); err == nil {
			t.Fatalf("someone@%s was accepted as a work address", d)
		}
	}
}

// The control --break-freemailsuffix matches the exact domain only. This
// is the test that notices.
func TestASubdomainOfAProviderIsRefusedToo(t *testing.T) {
	for _, d := range []string{"mail.yahoo.co.jp", "smtp.gmail.com", "abc123.mailinator.com", "x.y.guerrillamail.com"} {
		if !IsFreeMail(d) {
			t.Fatalf("%s, a subdomain of a provider, was not refused", d)
		}
	}
}

func TestACompanyDomainIsAccepted(t *testing.T) {
	for _, d := range []string{"kalesi.example", "arbor.example", "babbangona.com", "mail.kalesi.example", "example.co.uk"} {
		if IsFreeMail(d) {
			t.Fatalf("%s was refused", d)
		}
	}
	addr, domain, err := WorkEmail("Ada.Obi@Kalesi.Example")
	if err != nil || addr != "ada.obi@kalesi.example" || domain != "kalesi.example" {
		t.Fatalf("%q %q %v", addr, domain, err)
	}
}

func TestADeploymentAddsItsOwnRefusals(t *testing.T) {
	if IsFreeMail("freepost.example") {
		t.Fatal("the test domain is already refused")
	}
	path := filepath.Join(t.TempDir(), "blocked.txt")
	if err := os.WriteFile(path, []byte("# ours\nFreePost.Example \n\nnot a domain\nalso-free.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := LoadBlockedDomainsFile(path)
	if err != nil || n != 2 {
		t.Fatalf("added %d, %v", n, err)
	}
	if !IsFreeMail("freepost.example") || !IsFreeMail("mail.freepost.example") || !IsFreeMail("also-free.example") {
		t.Fatal("the deployment's domains are not refused")
	}
	if _, _, err := WorkEmail("x@freepost.example"); err == nil {
		t.Fatal("accepted")
	}
	// Adding again adds nothing; a missing file is an error that names it.
	if n, _ := LoadBlockedDomainsFile(path); n != 0 {
		t.Fatalf("added %d twice", n)
	}
	if _, err := LoadBlockedDomainsFile(filepath.Join(t.TempDir(), "none")); err == nil || !strings.Contains(err.Error(), "none") {
		t.Fatalf("missing file: %v", err)
	}
}
