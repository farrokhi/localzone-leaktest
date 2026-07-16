// Package report renders a run's results as either a human readable table or
// machine readable JSON.
package report

import (
	"strconv"
	"time"

	"github.com/farrokhi/localzone-leaktest/internal/classify"
	"github.com/farrokhi/localzone-leaktest/internal/runner"
)

// Options controls rendering.
type Options struct {
	Color   bool // emit ANSI color
	Verbose bool // show raw per name signal detail
	Quiet   bool // print only the summary
}

// queryTimeMS returns the round trip time in whole milliseconds, or -1 when the
// probe failed and no timing is meaningful.
func queryTimeMS(r classify.Result) int64 {
	if r.Verdict == classify.VerdictError && r.Probe.Err != nil {
		return -1
	}
	return r.Probe.RTT.Milliseconds()
}

// baselineMS renders the recursion baseline for display.
func baselineMS(s runner.Summary) string {
	if !s.BaselineOK {
		return "unavailable"
	}
	return formatMS(s.Baseline)
}

func formatMS(d time.Duration) string {
	ms := d.Milliseconds()
	if ms == 0 && d > 0 {
		return "<1 ms"
	}
	return strconv.FormatInt(ms, 10) + " ms"
}
