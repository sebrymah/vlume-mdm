//go:build windows

package agent

import "os"

// ownedByRoot has no meaning on Windows: there is no uid 0, and the thing
// it stands in for is an access control list rather than an owner.
//
// Check returns before reaching this, with a finding saying plainly that
// the permission checks are not implemented here. That is better than a
// clean bill of health that means nothing, which is what returning true
// from a stub would produce.
func ownedByRoot(os.FileInfo) bool { return true }
