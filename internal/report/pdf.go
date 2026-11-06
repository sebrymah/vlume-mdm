package report

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"strings"
	"time"

	"platform/internal/branding"
)

// A PDF, by hand. One font, one page size, a coloured band with the
// tenant's product name, a table of devices, the findings for anything not
// compliant, and a footer on every page: the document's title, then
// "Page N of M". Nothing in it names the operator, and the Producer field
// that a library would fill with its own name is left out.

const (
	pageW, pageH  = 595.0, 842.0 // A4, points
	marginX       = 40.0
	bandH         = 44.0
	lineH         = 13.0
	bodyTop       = pageH - bandH - 36
	bodyBottom    = 56.0
	fontBody      = 9.5
	fontHeading   = 12.0
	fontBand      = 15.0
	maxNameChars  = 26
	maxSerialChar = 16
)

var bodyHeight float64 = bodyTop - bodyBottom
var linesPerPage = int(bodyHeight / lineH)

type line struct {
	text string
	size float64
	bold bool
	x    float64
}

// Logo is the tenant's logo for the band, when it is a PNG or a JPEG;
// anything else draws the letter mark. Decoded here to raw samples so the
// PDF needs no image library at read time either.
type Logo struct {
	Width, Height int
	RGB           []byte // 8-bit RGB, row-major
}

// PDF writes the report in the tenant's brand.
func PDF(w io.Writer, r Report, b branding.Brand, title string) error {
	return PDFWithLogo(w, r, b, title, nil)
}

func PDFWithLogo(w io.Writer, r Report, b branding.Brand, title string, logo *Logo) error {
	lines := layout(r)
	pages := paginate(lines)
	if len(pages) == 0 {
		pages = [][]line{{}}
	}
	red, green, blue := rgb(b.Colour)

	var out bytes.Buffer
	var offsets []int
	obj := func(body string) int {
		offsets = append(offsets, out.Len())
		n := len(offsets)
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", n, body)
		return n
	}
	out.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

	// 1: catalog, 2: pages (filled in after we know the page objects),
	// 3: font. Objects are numbered in order of writing, so the pages
	// object is written as a placeholder of known size and patched.
	obj("<< /Type /Catalog /Pages 2 0 R >>")
	pagesAt := out.Len()
	placeholder := "<< /Type /Pages /Kids [" + strings.Repeat(" ", 12*len(pages)) + "] /Count " + fmt.Sprintf("%-6d", len(pages)) + " >>"
	obj(placeholder)
	obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
	obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
	logoObj := 0
	if logo != nil && logo.Width > 0 && logo.Height > 0 && len(logo.RGB) == logo.Width*logo.Height*3 {
		var z bytes.Buffer
		zw := zlib.NewWriter(&z)
		_, _ = zw.Write(logo.RGB)
		_ = zw.Close()
		logoObj = obj(fmt.Sprintf("<< /Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace /DeviceRGB "+
			"/BitsPerComponent 8 /Filter /FlateDecode /Length %d >>\nstream\n%s\nendstream",
			logo.Width, logo.Height, z.Len(), z.String()))
	}

	var kids []string
	footerTitle := title
	for i, page := range pages {
		var cs bytes.Buffer
		// The band, in the tenant's colour, with the product name in white.
		fmt.Fprintf(&cs, "q %.3f %.3f %.3f rg 0 %.1f %.1f %.1f re f Q\n", red, green, blue, pageH-bandH, pageW, bandH)
		nameX := marginX
		if logoObj > 0 {
			// The logo at the band's height, on a white tab, the name beside it.
			h := bandH - 12
			wdt := h * float64(logo.Width) / float64(logo.Height)
			if wdt > 110 {
				wdt = 110
			}
			fmt.Fprintf(&cs, "q 1 1 1 rg %.1f %.1f %.1f %.1f re f Q\n", marginX-4, pageH-bandH+2, wdt+8, bandH-4)
			fmt.Fprintf(&cs, "q %.1f 0 0 %.1f %.1f %.1f cm /Im1 Do Q\n", wdt, h, marginX, pageH-bandH+6)
			nameX = marginX + wdt + 14
		}
		fmt.Fprintf(&cs, "BT /F2 %.1f Tf 1 1 1 rg %.1f %.1f Td (%s) Tj ET\n",
			fontBand, nameX, pageH-bandH+15, esc(b.ProductName))
		fmt.Fprintf(&cs, "BT /F1 9 Tf 1 1 1 rg %.1f %.1f Td (%s) Tj ET\n",
			pageW-marginX-150, pageH-bandH+17, esc(r.GeneratedAt.UTC().Format("2 Jan 2006 15:04 UTC")))
		// The body.
		y := bodyTop
		for _, ln := range page {
			font := "/F1"
			if ln.bold {
				font = "/F2"
			}
			fmt.Fprintf(&cs, "BT %s %.1f Tf 0 0 0 rg %.1f %.1f Td (%s) Tj ET\n",
				font, ln.size, marginX+ln.x, y, esc(ln.text))
			y -= lineH
		}
		// The footer: title, then Page N of M. On every page.
		footer := fmt.Sprintf("%s  \u00b7  Page %d of %d", footerTitle, i+1, len(pages))
		fmt.Fprintf(&cs, "BT /F1 8 Tf 0.35 0.35 0.35 rg %.1f 30 Td (%s) Tj ET\n", marginX, esc(footer))
		if b.LegalFooter != "" {
			fmt.Fprintf(&cs, "BT /F1 8 Tf 0.35 0.35 0.35 rg %.1f 18 Td (%s) Tj ET\n", marginX, esc(b.LegalFooter))
		}
		content := obj(fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", cs.Len(), cs.String()))
		resources := "/Font << /F1 3 0 R /F2 4 0 R >>"
		if logoObj > 0 {
			resources += fmt.Sprintf(" /XObject << /Im1 %d 0 R >>", logoObj)
		}
		pageObj := obj(fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.0f %.0f] "+
			"/Resources << %s >> /Contents %d 0 R >>", pageW, pageH, resources, content))
		kids = append(kids, fmt.Sprintf("%d 0 R", pageObj))
	}

	// Patch the pages object in place, keeping its length.
	filled := "<< /Type /Pages /Kids [" + strings.Join(kids, " ")
	filled += strings.Repeat(" ", len(placeholder)-len(filled)-len("] /Count "+fmt.Sprintf("%-6d", len(pages))+" >>"))
	filled += "] /Count " + fmt.Sprintf("%-6d", len(pages)) + " >>"
	buf := out.Bytes()
	copy(buf[pagesAt+len("2 0 obj\n"):], []byte(filled))

	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(offsets)+1)
	for _, off := range offsets {
		fmt.Fprintf(&out, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offsets)+1, xref)
	_, err := w.Write(out.Bytes())
	return err
}

func layout(r Report) []line {
	var ls []line
	add := func(text string, size float64, bold bool, x float64) {
		ls = append(ls, line{text: text, size: size, bold: bold, x: x})
	}
	add("Compliance report", fontHeading, true, 0)
	add(r.Summary(), fontBody, false, 0)
	add("", fontBody, false, 0)
	add(pad("Device", 28)+pad("Serial", 18)+pad("OS", 10)+pad("Verdict", 16)+"Last reported", fontBody, true, 0)
	for _, row := range r.Rows {
		reported := "never"
		if row.ReportedAt != nil {
			reported = row.ReportedAt.UTC().Format("2 Jan 2006 15:04")
		}
		add(pad(clip(row.Name, maxNameChars), 28)+pad(clip(row.Serial, maxSerialChar), 18)+
			pad(row.OSFamily, 10)+pad(Words(row.Verdict), 16)+reported, fontBody, false, 0)
	}
	var trouble []Row
	for _, row := range r.Rows {
		if len(row.Findings) > 0 && row.Verdict != "retired" {
			trouble = append(trouble, row)
		}
	}
	if len(trouble) > 0 {
		add("", fontBody, false, 0)
		add("What is wrong, and which policy asked", fontHeading, true, 0)
		for _, row := range trouble {
			add("", fontBody, false, 0)
			add(row.Name+"  ("+row.Serial+")", fontBody, true, 0)
			for _, f := range row.Findings {
				add(f.Rule+": "+f.Saw+"  ["+f.From+"]", fontBody, false, 12)
			}
		}
	}
	return ls
}

func paginate(ls []line) [][]line {
	var pages [][]line
	for len(ls) > 0 {
		n := linesPerPage
		if n > len(ls) {
			n = len(ls)
		}
		pages = append(pages, ls[:n])
		ls = ls[n:]
	}
	return pages
}

func pad(s string, n int) string {
	if len(s) >= n {
		return s[:n-1] + " "
	}
	return s + strings.Repeat(" ", n-len(s))
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "~"
}

// esc makes a string safe inside a PDF literal: the three characters that
// mean something, and anything outside Latin-1, which Helvetica cannot
// draw, replaced rather than silently dropped.
func esc(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '(' || r == ')' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case r > 255:
			b.WriteByte('?')
		default:
			b.WriteByte(byte(r))
		}
	}
	return b.String()
}

func rgb(hex string) (float64, float64, float64) {
	hex = strings.TrimPrefix(hex, "#")
	if len(hex) != 6 {
		return 0.06, 0.43, 0.40
	}
	var r, g, b int
	if _, err := fmt.Sscanf(hex, "%02x%02x%02x", &r, &g, &b); err != nil {
		return 0.06, 0.43, 0.40
	}
	return float64(r) / 255, float64(g) / 255, float64(b) / 255
}

// Filename is what the download is called: the product's name and the
// day, so a folder of them reads in order.
func Filename(b branding.Brand, at time.Time, ext string) string {
	name := strings.ToLower(strings.TrimSpace(b.ProductName))
	if b.IsPlaceholder() {
		name = "compliance"
	}
	var out strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			out.WriteRune(r)
		case r == ' ' || r == '-' || r == '_':
			out.WriteByte('-')
		}
	}
	return out.String() + "-compliance-" + at.UTC().Format("2006-01-02") + "." + ext
}
