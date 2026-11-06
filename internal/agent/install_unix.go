//go:build !windows

package agent

import (
	"os"
	"syscall"
)

// ownedByRoot is the Unix answer. It is in its own file because syscall's
// Stat_t does not exist on Windows at all, which the cross-compile caught
// the first time these binaries were built for every platform rather than
// just the one this was written on.
func ownedByRoot(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		// A filesystem that does not report an owner. Answering "yes, root"
		// here would read as a pass; answering "no" would report a problem
		// nobody can fix. The caller only asks on platforms where the
		// question means something, so this is the unreachable case.
		return true
	}
	return st.Uid == 0
}
