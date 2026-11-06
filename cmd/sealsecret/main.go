// Command sealsecret seals an identity provider client secret so it can be
// pasted into a tenant_identity row.
//
// This is the setup wizard's one irreducible step, done at a terminal until
// the wizard exists. It is a separate command rather than a flag on the
// gateway because the gateway should never be a thing you run to transform a
// secret, and because this way the secret is typed into a prompt on one
// machine and never becomes a command-line argument that lands in a shell
// history file.
//
//	MDM_SEALING_KEY=... go run ./cmd/sealsecret
//	paste the client secret, press enter
//
// It prints the PostgreSQL bytea literal to put in client_secret_sealed.
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"platform/internal/platformkeys"
	"platform/internal/secrets"
)

func main() {
	// The same source the gateway reads (MDM_KEY_SOURCE): the key
	// directory, the vault, or MDM_SEALING_KEY in the environment. It
	// must be the key the gateway runs with, or the gateway cannot open
	// what this seals.
	src, err := platformkeys.Choose(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	key, _, err := platformkeys.LoadSealing(context.Background(), src)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sealer, err := secrets.NewAESSealer(key)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Fprint(os.Stderr, "client secret: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		fmt.Fprintln(os.Stderr, "nothing to seal")
		os.Exit(1)
	}
	plain := strings.TrimRight(line, "\r\n")
	if plain == "" {
		fmt.Fprintln(os.Stderr, "nothing to seal")
		os.Exit(1)
	}

	sealed, err := sealer.Seal([]byte(plain))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// Only the sealed form reaches stdout, so piping this into a file or a
	// clipboard cannot leak the secret itself.
	fmt.Printf("\\x%s\n", hex.EncodeToString(sealed))
}
