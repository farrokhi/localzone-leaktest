package report

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/farrokhi/localzone-leaktest/internal/classify"
	"github.com/farrokhi/localzone-leaktest/internal/runner"
)

// ANSI color codes, applied only when Options.Color is set.
const (
	ansiReset   = "\033[0m"
	ansiGreen   = "\033[32m"
	ansiRed     = "\033[31m"
	ansiBoldRed = "\033[1;31m"
	ansiYellow  = "\033[33m"
	ansiDim     = "\033[2m"
)

// maxNameWidth caps the name column so a 72 character IPv6 reverse zone does not
// push every other column off screen. Longer names are middle truncated.
const maxNameWidth = 44

// markerWidth is the STATUS column width, sized to the widest marker "[INCONCL]".
const markerWidth = 9

// ew wraps an io.Writer and remembers the first write error, so the report can
// be emitted as a straight sequence of writes and the error surfaced once at the
// end instead of being checked after every call.
type ew struct {
	w   io.Writer
	err error
}

func (e *ew) printf(format string, a ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, a...)
}

func (e *ew) println(a ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintln(e.w, a...)
}

// Human writes the human readable report to w and returns the first write error,
// if any (for example a broken pipe when the output is piped into head).
func Human(w io.Writer, rep *runner.Report, opts Options) error {
	e := &ew{w: w}
	s := rep.Summary

	if !opts.Quiet {
		e.printf("Resolver: %s    Recursion baseline: %s\n\n", s.Resolver, baselineMS(s))
		writeTable(e, rep.Results, opts)
		e.println()
	}
	writeSummary(e, s, opts)
	return e.err
}

func writeTable(e *ew, results []classify.Result, opts Options) {
	nameW := 4 // len("NAME")
	catW := 8  // len("CATEGORY")
	for _, r := range results {
		if n := len(displayName(r.Zone.Name)); n > nameW {
			nameW = n
		}
		if n := len(r.Zone.Category); n > catW {
			catW = n
		}
	}
	if nameW > maxNameWidth {
		nameW = maxNameWidth
	}

	e.printf("%-*s  %-*s  %-*s  %8s  %s\n",
		nameW, "NAME", catW, "CATEGORY", markerWidth, "STATUS", "TIME", "SOURCE")

	for _, r := range results {
		marker := colorize(markerText(r.Verdict), r.Verdict, opts.Color)
		// Pad the marker on its plain text width so color codes do not distort
		// column alignment.
		markerPad := strings.Repeat(" ", markerWidth-len(markerText(r.Verdict)))
		e.printf("%-*s  %-*s  %s%s  %8s  %s\n",
			nameW, displayName(r.Zone.Name),
			catW, r.Zone.Category,
			marker, markerPad,
			timeCell(r),
			r.Source)

		if opts.Verbose {
			writeVerbose(e, r, opts)
		}
	}
}

func writeVerbose(e *ew, r classify.Result, opts Options) {
	rcode := r.Probe.RCodeText
	if rcode == "" {
		rcode = "-"
	}
	ede := "none"
	if r.Probe.EDECode >= 0 {
		ede = strconv.Itoa(r.Probe.EDECode)
		if r.Probe.EDEText != "" {
			ede += " (" + r.Probe.EDEText + ")"
		}
	}
	soa := r.Probe.SOAMName
	if soa == "" {
		soa = "none"
	}
	owner := r.Probe.SOAOwner
	if owner == "" {
		owner = "none"
	}
	rd0 := r.RD0
	if rd0 == "" {
		rd0 = "-"
	}
	detail := fmt.Sprintf("    rcode=%s  aa=%v  soa_owner=%s  soa_mname=%s  ede=%s  rd0=%s  qtime=%dms",
		rcode, r.Probe.AA, owner, soa, ede, rd0, r.Probe.RTT.Milliseconds())
	if opts.Color {
		detail = ansiDim + detail + ansiReset
	}
	e.println(detail)
}

func writeSummary(e *ew, s runner.Summary, opts Options) {
	local := s.Counts[classify.VerdictLocal]
	leak := s.Counts[classify.VerdictLeak]
	hijack := s.Counts[classify.VerdictHijack]
	inconcl := s.Counts[classify.VerdictInconclusive]
	errs := s.Counts[classify.VerdictError]

	e.printf("Summary: %d local, %d leaked, %d hijacked, %d inconclusive, %d errors (of %d tested)\n",
		local, leak, hijack, inconcl, errs, s.Total)

	var line string
	var verdict classify.Verdict
	switch {
	case leak == 0 && hijack == 0 && inconcl == 0 && errs == 0:
		line = fmt.Sprintf("%d of %d names handled locally, no leaks.", local, s.Total)
		verdict = classify.VerdictLocal
	case hijack > 0:
		line = fmt.Sprintf("%d %s hijacked and %d leaked to the public DNS.", hijack, noun(hijack), leak)
		verdict = classify.VerdictHijack
	case leak > 0:
		line = fmt.Sprintf("%d %s leaked to the public DNS.", leak, noun(leak))
		verdict = classify.VerdictLeak
	case inconcl > 0:
		line = fmt.Sprintf("no confirmed leaks, but %d %s inconclusive.", inconcl, noun(inconcl))
		verdict = classify.VerdictInconclusive
	default:
		line = fmt.Sprintf("no leaks, but %d %s could not be tested cleanly.", errs, noun(errs))
		verdict = classify.VerdictError
	}
	e.println(colorize(line, verdict, opts.Color))
}

// noun returns "name" or "names" to agree with a count.
func noun(n int) string {
	if n == 1 {
		return "name"
	}
	return "names"
}

func timeCell(r classify.Result) string {
	if ms := queryTimeMS(r); ms >= 0 {
		return strconv.FormatInt(ms, 10) + "ms"
	}
	return "-"
}

func markerText(v classify.Verdict) string {
	switch v {
	case classify.VerdictLocal:
		return "[LOCAL]"
	case classify.VerdictLeak:
		return "[LEAK]"
	case classify.VerdictHijack:
		return "[HIJACK]"
	case classify.VerdictInconclusive:
		return "[INCONCL]"
	default:
		return "[ERROR]"
	}
}

func colorize(text string, v classify.Verdict, color bool) string {
	if !color {
		return text
	}
	var code string
	switch v {
	case classify.VerdictLocal:
		code = ansiGreen
	case classify.VerdictLeak:
		code = ansiRed
	case classify.VerdictHijack:
		code = ansiBoldRed
	default: // INCONCLUSIVE and ERROR
		code = ansiYellow
	}
	return code + text + ansiReset
}

// displayName middle truncates names longer than maxNameWidth, keeping the head
// and the tail (which carries the ip6.arpa / in-addr.arpa suffix).
func displayName(name string) string {
	if len(name) <= maxNameWidth {
		return name
	}
	keep := maxNameWidth - 3
	head := keep / 2
	tail := keep - head
	return name[:head] + "..." + name[len(name)-tail:]
}
