// Package qr draws text as a QR code a phone can scan.
//
// It exists because a thing a person has to pass to a phone is better
// scanned than typed. Two payloads need it: Google's enrolment link for a
// personal phone (the camera opens it), and Google's provisioning payload
// for a company phone (read by the welcome screen after six taps). Until
// this package the second was printed as raw text with a suggestion to use
// somebody else's QR generator, which is a sentence that ends a rollout.
//
// The image is a PNG inside a data: URL. Nothing is fetched from anywhere,
// so the secret in the payload never leaves the page it was made for, and a
// test can decode the picture back to the exact text, which is the only
// honest test of a QR code.
package qr

import (
	"encoding/base64"
	"errors"
	"html/template"

	rsc "rsc.io/qr"
)

// ErrEmpty is nothing to draw.
var ErrEmpty = errors.New("qr: nothing to encode")

// denseAbove is the payload length past which error correction drops to its
// lowest level. A provisioning payload runs to several hundred bytes; at the
// higher levels it becomes a grid of tiny squares that a welcome screen's
// scanner struggles with. A short link keeps the stronger correction, which
// survives a cracked screen or a glossy printout.
const denseAbove = 300

// DataURL draws text as a QR code and returns it as a data: URL for an
// <img>. The type is template.URL because html/template, quite properly,
// refuses data: in a src unless told the value is ours.
func DataURL(text string) (template.URL, error) {
	if text == "" {
		return "", ErrEmpty
	}
	png, err := PNG(text)
	if err != nil {
		return "", err
	}
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png)), nil
}

// PNG is the picture itself, with a quiet zone, at a size that is easy to
// scan from a screen held at arm's length.
func PNG(text string) ([]byte, error) {
	if text == "" {
		return nil, ErrEmpty
	}
	level := rsc.M
	if len(text) > denseAbove {
		level = rsc.L
	}
	c, err := rsc.Encode(text, level)
	if err != nil {
		return nil, err
	}
	// About 400 pixels across whatever the density, never smaller than
	// four pixels a square.
	scale := 400 / (c.Size + 8)
	if scale < 4 {
		scale = 4
	}
	c.Scale = scale
	return c.PNG(), nil
}
