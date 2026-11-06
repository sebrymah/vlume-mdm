package agent

import (
	"net"
	"testing"
)

func hw(s string) net.HardwareAddr {
	a, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return a
}

// A Mac with Docker Desktop and a VPN, as net.Interfaces lists it: the
// card and the Wi-Fi are reported, the rest is not.
func TestOnlyTheNetworkCardsAreReported(t *testing.T) {
	got := pickHardwareAddresses([]iface{
		{Name: "lo0", Flags: net.FlagLoopback | net.FlagUp},
		{Name: "en0", Flags: net.FlagUp, Addr: hw("3C:22:FB:AA:BB:01")},
		{Name: "en5", Flags: net.FlagUp, Addr: hw("ac:de:48:00:11:22")},
		{Name: "awdl0", Flags: net.FlagUp, Addr: hw("4a:5c:11:22:33:44")},
		{Name: "llw0", Flags: net.FlagUp, Addr: hw("4a:5c:11:22:33:44")},
		{Name: "utun3", Flags: net.FlagUp},
		{Name: "bridge100", Flags: net.FlagUp, Addr: hw("3e:22:fb:aa:bb:64")},
		{Name: "vmnet8", Flags: net.FlagUp, Addr: hw("00:50:56:c0:00:08")},
		{Name: "docker0", Flags: net.FlagUp, Addr: hw("02:42:ac:11:00:01")},
		{Name: "gif0"}, {Name: "stf0"},
	})
	want := []string{"3c:22:fb:aa:bb:01", "ac:de:48:00:11:22"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestAWindowsPCsVirtualAdaptersAreLeftOut(t *testing.T) {
	got := pickHardwareAddresses([]iface{
		{Name: "Ethernet", Flags: net.FlagUp, Addr: hw("A4-BB-6D-11-22-33")},
		{Name: "Wi-Fi", Flags: net.FlagUp, Addr: hw("F0-9E-4A-44-55-66")},
		{Name: "vEthernet (WSL)", Flags: net.FlagUp, Addr: hw("00-15-5D-01-02-03")},
		{Name: "VirtualBox Host-Only Network", Flags: net.FlagUp, Addr: hw("0A-00-27-00-00-0C")},
		{Name: "Loopback Pseudo-Interface 1", Flags: net.FlagLoopback | net.FlagUp},
		{Name: "Wi-Fi", Flags: net.FlagUp, Addr: hw("F0-9E-4A-44-55-66")}, // listed twice: once
	})
	if len(got) != 2 || got[0] != "a4:bb:6d:11:22:33" || got[1] != "f0:9e:4a:44:55:66" {
		t.Fatalf("got %v", got)
	}
}
