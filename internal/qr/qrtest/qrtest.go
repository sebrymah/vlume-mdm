// Package qrtest reads QR codes back out of pictures, for tests. It is the
// phone's side of the transaction, done by a decoder that shares no code
// with the one that drew the picture. Only tests import it.
package qrtest

import (
	"bytes"
	"encoding/base64"
	"html"
	"image/png"
	"strings"
	"testing"

	"github.com/makiuchi-d/gozxing"
	zxqr "github.com/makiuchi-d/gozxing/qrcode"
)

// Scan reads the text out of a PNG, as a camera would.
func Scan(t testing.TB, pngBytes []byte) string {
	t.Helper()
	img, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		t.Fatalf("not a PNG: %v", err)
	}
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		t.Fatal(err)
	}
	res, err := zxqr.NewQRCodeReader().Decode(bmp, nil)
	if err != nil {
		t.Fatalf("the picture does not scan: %v", err)
	}
	return res.GetText()
}

// ScanDataURL reads the text out of a data:image/png;base64 URL.
func ScanDataURL(t testing.TB, u string) string {
	t.Helper()
	raw, ok := strings.CutPrefix(u, "data:image/png;base64,")
	if !ok {
		t.Fatalf("not a PNG data URL: %.60s", u)
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("bad base64: %v", err)
	}
	return Scan(t, b)
}

// PageImages returns every data:image/png URL on an HTML page, in order.
func PageImages(page string) []string {
	var out []string
	for {
		i := strings.Index(page, `src="data:image/png;base64,`)
		if i < 0 {
			return out
		}
		page = page[i+len(`src="`):]
		j := strings.IndexByte(page, '"')
		if j < 0 {
			return out
		}
		// An attribute value arrives HTML-escaped (a + is &#43;). A browser
		// undoes that before it uses the address, so the helper does too.
		out = append(out, html.UnescapeString(page[:j]))
		page = page[j:]
	}
}
