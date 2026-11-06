package console

import (
	"fmt"
	"strings"

	"platform/internal/data"
)

// The dashboard's trend: one line, the share of the fleet that is
// compliant, over the last thirty days. One series, so no legend; the
// title names it, the last point is labelled, and the days are a table
// under it for anyone who wants the numbers.

type TrendLine struct {
	Width, Height int
	// Path is the line, Points the markers, each with its own title for
	// the hover.
	Path   string
	Points []TrendPoint
	// Latest is the last day's share, for the label beside the line.
	Latest int
	// Days is how many points there are.
	Days int
}

type TrendPoint struct {
	X, Y  float64
	Title string
}

// DrawTrend lays the snapshots out on a width by height box. Fewer than
// two days is nothing to draw: a line needs two ends, and the dashboard
// says so instead.
func DrawTrend(days []data.ComplianceSnapshot, width, height int) *TrendLine {
	if len(days) < 2 {
		return nil
	}
	const pad = 6.0
	w, h := float64(width), float64(height)
	t := &TrendLine{Width: width, Height: height, Days: len(days)}
	var sb strings.Builder
	for i, d := range days {
		share := 0.0
		if d.Total > 0 {
			share = float64(d.Compliant) / float64(d.Total)
		}
		x := pad + (w-2*pad)*float64(i)/float64(len(days)-1)
		y := pad + (h-2*pad)*(1-share)
		if i == 0 {
			fmt.Fprintf(&sb, "M%.1f %.1f", x, y)
		} else {
			fmt.Fprintf(&sb, " L%.1f %.1f", x, y)
		}
		t.Points = append(t.Points, TrendPoint{X: x, Y: y,
			Title: fmt.Sprintf("%s: %d of %d compliant", d.TakenOn.Format("2 Jan"), d.Compliant, d.Total)})
		if i == len(days)-1 {
			t.Latest = int(share*100 + 0.5)
		}
	}
	t.Path = sb.String()
	return t
}
