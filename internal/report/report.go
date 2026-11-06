// Package report is F18: the compliance report, as CSV and as PDF, on
// demand and on a schedule.
//
// A report is an export of tenant data, so it is read under the tenant's
// claim like everything else, it is audited when it is made, and it carries
// the tenant's own brand and nobody else's (T4, T12). The PDF is written by
// hand rather than through a library: it is text on pages with a coloured
// band and a footer, and a dependency that could put its own producer
// string on a tenant's document is a dependency this package does not want.
package report

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"platform/internal/data"
	"platform/internal/policy"
)

type Row struct {
	DeviceID   uuid.UUID
	Name       string
	Serial     string
	OSFamily   string
	Ownership  string
	AssignedTo string
	State      string
	// Verdict is the engine's view at read time, stale re-checked, which
	// can differ from the device's stored state for a device that has
	// gone quiet since it was judged.
	Verdict    string
	ReportedAt *time.Time
	Findings   []policy.Finding
	Policies   []string
}

type Report struct {
	GeneratedAt time.Time
	Rows        []Row
	// The summary the scheduled message carries and the PDF opens with.
	Total, Compliant, NotCompliant, Unknown, Quarantined, Retired, NeverReported int
}

// Compliance gathers the report. Every device the tenant has, in name
// order, with the verdict as the engine would give it right now.
func Compliance(ctx context.Context, tx *data.Tx, now time.Time) (Report, error) {
	devices, err := data.ListDevices(ctx, tx)
	if err != nil {
		return Report{}, err
	}
	rep := Report{GeneratedAt: now}
	for _, d := range devices {
		row := Row{
			DeviceID: d.ID, Name: d.Name, Serial: d.Serial, OSFamily: d.OSFamily,
			Ownership: d.Ownership, AssignedTo: d.AssignedTo, State: d.State,
		}
		c, found, err := policy.Of(ctx, tx, d.ID, now)
		if err != nil {
			return Report{}, err
		}
		switch {
		case d.State == "quarantined" || d.State == "retired":
			row.Verdict = d.State
		case !found:
			row.Verdict = "never_reported"
		default:
			row.Verdict = c.State
		}
		if found {
			t := c.ReportedAt
			row.ReportedAt = &t
			row.Findings = c.Findings
			row.Policies = c.Policies
		}
		rep.Rows = append(rep.Rows, row)
		rep.Total++
		switch row.Verdict {
		case policy.Compliant:
			rep.Compliant++
		case policy.NotCompliant:
			rep.NotCompliant++
		case policy.Unknown:
			rep.Unknown++
		case "quarantined":
			rep.Quarantined++
		case "retired":
			rep.Retired++
		case "never_reported":
			rep.NeverReported++
		}
	}
	sort.SliceStable(rep.Rows, func(i, j int) bool { return rep.Rows[i].Name < rep.Rows[j].Name })
	return rep, nil
}

// Summary is one sentence, for the scheduled message's subject line.
func (r Report) Summary() string {
	return fmt.Sprintf("%d devices: %d compliant, %d not compliant, %d unknown, %d quarantined, %d never reported",
		r.Total, r.Compliant, r.NotCompliant, r.Unknown, r.Quarantined, r.NeverReported)
}

// ---------------------------------------------------------------- CSV

// CSV writes one row per device. Findings are joined into one cell with
// the policy that asked, so a spreadsheet filter on the state column and a
// read of the findings column is the whole triage.
func CSV(w io.Writer, r Report) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"device", "serial", "os", "ownership", "assigned_to",
		"verdict", "last_reported", "findings", "policies"}); err != nil {
		return err
	}
	for _, row := range r.Rows {
		reported := ""
		if row.ReportedAt != nil {
			reported = row.ReportedAt.UTC().Format(time.RFC3339)
		}
		if err := cw.Write([]string{row.Name, row.Serial, row.OSFamily, row.Ownership, row.AssignedTo,
			row.Verdict, reported, findingsText(row.Findings, "; "), strings.Join(row.Policies, "; ")}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func findingsText(fs []policy.Finding, sep string) string {
	parts := make([]string, 0, len(fs))
	for _, f := range fs {
		s := f.Rule + " (" + f.Saw + ", " + f.From + ")"
		parts = append(parts, s)
	}
	return strings.Join(parts, sep)
}

// Words is how a verdict reads on paper.
func Words(verdict string) string {
	switch verdict {
	case policy.Compliant:
		return "Compliant"
	case policy.NotCompliant:
		return "Not compliant"
	case policy.Unknown:
		return "Unknown"
	case "never_reported":
		return "Never reported"
	case "quarantined":
		return "Quarantined"
	case "retired":
		return "Retired"
	}
	return verdict
}

// DecodeLogo turns a stored PNG or JPEG into samples for the PDF band. Any
// other type, or a decode failure, is nil: the band draws the name alone.
func DecodeLogo(b []byte, typ string) *Logo {
	if typ != "image/png" && typ != "image/jpeg" {
		return nil
	}
	img, _, err := image.Decode(bytes.NewReader(b))
	if err != nil {
		return nil
	}
	bounds := img.Bounds()
	w, h := bounds.Dx(), bounds.Dy()
	if w <= 0 || h <= 0 || w*h > 400*400 {
		// Larger than a band needs; the console caps bytes, not pixels, so
		// a huge flat PNG is possible. Skip rather than bloat the file.
		return nil
	}
	rgb := make([]byte, 0, w*h*3)
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			r, g, bl, a := img.At(x, y).RGBA()
			// Flatten onto white: the band tab behind the logo is white.
			r, g, bl = r>>8, g>>8, bl>>8
			a8 := a >> 8
			rgb = append(rgb, byte((r*a8+255*(255-a8))/255), byte((g*a8+255*(255-a8))/255), byte((bl*a8+255*(255-a8))/255))
		}
	}
	return &Logo{Width: w, Height: h, RGB: rgb}
}
