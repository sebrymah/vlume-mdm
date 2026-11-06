package android

import (
	"context"
	"errors"
	"fmt"

	"platform/internal/branding"
	"platform/internal/command"
)

// Push is the command pipeline's Android channel: Google carries the
// command out, so this is an Executor. The pipeline's own rules have all
// run by the time a command reaches here: the reason, the role, the second
// approval for a full wipe. This only decides which Google call that is.
type Push struct {
	Provider Provider
}

func (Push) Name() string            { return "Android Enterprise" }
func (Push) Executes(os string) bool { return os == "android" }

func (p Push) Push(ctx context.Context, t command.PushTarget) error {
	if t.OSFamily != "android" {
		return errors.New("android: not an Android device")
	}
	if t.Tx == nil {
		return errors.New("android: the push target carries no transaction")
	}
	name, err := AndroidName(ctx, t.Tx, t.DeviceID)
	if err != nil {
		return err
	}
	switch t.Type {
	case command.Lock:
		return p.Provider.IssueCommand(ctx, name, Lock)
	case command.ClearPasscode:
		return p.Provider.IssueCommand(ctx, name, ResetPassword)
	case command.WipeSelective:
		// The work profile goes; the person's own data stays.
		return p.Provider.Wipe(ctx, name, true)
	case command.WipeFull:
		return p.Provider.Wipe(ctx, name, false)
	case command.LostMode:
		// What the lock screen says is the TENANT's name and words. The
		// operator-brand rule applies to a found phone exactly as it does
		// to a page: whoever picks it up sees who it belongs to.
		b, err := branding.Load(ctx, t.Tx)
		if err != nil {
			return err
		}
		return p.Provider.StartLostMode(ctx, name, lostWords(b))
	case command.LostModeEnd:
		return p.Provider.StopLostMode(ctx, name)
	}
	return fmt.Errorf("android: no Google command for %s", t.Type)
}

// lostWords is the lock-screen message, from the tenant's brand.
func lostWords(b branding.Brand) LostModeInput {
	org := b.ProductName
	if b.IsPlaceholder() {
		org = "its owner"
	}
	msg := "This device is managed by " + org + " and has been reported lost. "
	switch {
	case b.LostPhone != "" && b.LostEmail != "":
		msg += "If you have found it, please call " + b.LostPhone + " or email " + b.LostEmail + "."
	case b.LostPhone != "":
		msg += "If you have found it, please call " + b.LostPhone + "."
	case b.LostEmail != "":
		msg += "If you have found it, please email " + b.LostEmail + "."
	default:
		msg += "If you have found it, please hand it in; the owner has been told."
	}
	return LostModeInput{Message: msg, Organisation: org, Email: b.LostEmail, Phone: b.LostPhone}
}
