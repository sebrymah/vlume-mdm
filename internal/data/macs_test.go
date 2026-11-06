package data

import "testing"

// Every way real equipment writes a MAC lands on the one form the table
// holds. The control --break-macnormalise keeps the separators, and the
// Cisco form stops matching.
func TestEveryWayOfWritingAMACIsOneAddress(t *testing.T) {
	for _, in := range []string{
		"3c:22:fb:aa:bb:01", "3C:22:FB:AA:BB:01", "3C-22-FB-AA-BB-01", "3c22.fbaa.bb01", "3C22FBAABB01", " 3c:22:fb:aa:bb:01\n",
	} {
		got, ok := NormaliseMAC(in)
		if !ok || got != "3c:22:fb:aa:bb:01" {
			t.Fatalf("%q -> %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "not a mac", "3c:22:fb:aa:bb", "3c:22:fb:aa:bb:01:02", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "zz:22:fb:aa:bb:01"} {
		if got, ok := NormaliseMAC(in); ok {
			t.Fatalf("%q was taken as %q", in, got)
		}
	}
}
