package agent

import (
	"net"
	"strings"
)

// The hardware addresses this machine's interfaces carry, for the
// network's door: a NAC knows a device by the address it authenticated
// with, not by its serial. Physical interfaces only, as far as a name can
// tell: the virtual ones a container runtime, a VPN or a hypervisor adds
// carry addresses no switch will ever see, and reporting them would let a
// device claim addresses that are not on the network.

// virtualPrefixes are the interface names that are not a network card.
var virtualPrefixes = []string{
	"lo", "docker", "veth", "br-", "virbr", "vmnet", "vboxnet", "utun", "tun", "tap",
	"awdl", "llw", "bridge", "ap", "gif", "stf", "anpi", "ipsec", "wg", "tailscale",
	"zt", "ham", "vEthernet", "Hyper-V", "VirtualBox", "VMware", "Loopback", "Teredo", "isatap",
}

type iface struct {
	Name  string
	Flags net.Flags
	Addr  net.HardwareAddr
}

func hardwareAddresses() []string {
	list, err := net.Interfaces()
	if err != nil {
		return nil
	}
	in := make([]iface, 0, len(list))
	for _, i := range list {
		in = append(in, iface{Name: i.Name, Flags: i.Flags, Addr: i.HardwareAddr})
	}
	return pickHardwareAddresses(in)
}

// pickHardwareAddresses is the pure part, so it can be held to a list of
// interfaces a real machine has.
func pickHardwareAddresses(in []iface) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, i := range in {
		if i.Flags&net.FlagLoopback != 0 || len(i.Addr) != 6 {
			continue
		}
		if isVirtual(i.Name) {
			continue
		}
		mac := strings.ToLower(i.Addr.String())
		if mac == "00:00:00:00:00:00" || seen[mac] {
			continue
		}
		seen[mac] = true
		out = append(out, mac)
		if len(out) >= 16 {
			break
		}
	}
	return out
}

func isVirtual(name string) bool {
	lower := strings.ToLower(name)
	for _, p := range virtualPrefixes {
		if strings.HasPrefix(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}
