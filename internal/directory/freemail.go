package directory

import (
	"bufio"
	_ "embed"
	"fmt"
	"os"
	"strings"
	"sync"
)

// The domains anyone can get an address at: the free-mail providers and
// the disposable-address services, thirty-two thousand of them, built
// from two maintained public lists (the file says which) and shipped in
// the binary so a sign-up is judged the same wherever the gateway runs.
//
// Two things make the list more than a list. A subdomain of any entry is
// refused too, so mail.yahoo.co.jp or a disposable service's per-user
// hostnames are caught by the parent. And a deployment can add its own
// refusals from a file (MDM_SIGNUP_BLOCKED_DOMAINS_FILE), for the provider
// that is big in one country and missing from both lists.
//
// What it does not do is look up the domain's mail exchanger. A company on
// Google Workspace has Google's servers as its exchanger and is a company
// all the same; the question is whether anyone can get an address there,
// and that is a fact about the domain, not about who carries its mail.

//go:embed freemail_domains.txt
var freeMailData string

var (
	freeMailOnce sync.Once
	freeMailSet  map[string]struct{}
	freeMailMu   sync.RWMutex
	extraBlocked = map[string]struct{}{}
)

func freeMail() map[string]struct{} {
	freeMailOnce.Do(func() {
		freeMailSet = make(map[string]struct{}, 33000)
		sc := bufio.NewScanner(strings.NewReader(freeMailData))
		for sc.Scan() {
			d := strings.TrimSpace(sc.Text())
			if d == "" || strings.HasPrefix(d, "#") {
				continue
			}
			freeMailSet[d] = struct{}{}
		}
	})
	return freeMailSet
}

// FreeMailCount is how many domains the shipped list holds.
func FreeMailCount() int { return len(freeMail()) }

// IsFreeMail says whether the domain, or any parent of it, is one anyone
// can get an address at. The domain is lower-cased by the caller.
func IsFreeMail(domain string) bool {
	set := freeMail()
	freeMailMu.RLock()
	defer freeMailMu.RUnlock()
	labels := strings.Split(domain, ".")
	// Every suffix with at least two labels: a.b.c.d, b.c.d, c.d. Never
	// the bare top level, which is not a provider.
	for i := 0; i < len(labels)-1; i++ {
		candidate := strings.Join(labels[i:], ".")
		if _, ok := set[candidate]; ok {
			return true
		}
		if _, ok := extraBlocked[candidate]; ok {
			return true
		}
	}
	return false
}

// AddBlockedDomains adds a deployment's own refusals. Returns how many
// were new. Lower-cased and trimmed; a line that is not a domain is
// skipped rather than refused, because a comment in the file is not a
// reason to refuse to start.
func AddBlockedDomains(domains []string) int {
	freeMailMu.Lock()
	defer freeMailMu.Unlock()
	added := 0
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || strings.HasPrefix(d, "#") || !strings.Contains(d, ".") || strings.ContainsAny(d, " @/") {
			continue
		}
		if _, dup := extraBlocked[d]; dup {
			continue
		}
		extraBlocked[d] = struct{}{}
		added++
	}
	return added
}

// LoadBlockedDomainsFile reads one domain per line, # for comments, and
// adds them. Returns how many were added.
func LoadBlockedDomainsFile(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("directory: blocked domains file: %w", err)
	}
	return AddBlockedDomains(strings.Split(string(b), "\n")), nil
}
