package cli

import (
	"testing"

	"github.com/farrokhi/localzone-leaktest/internal/classify"
	"github.com/farrokhi/localzone-leaktest/internal/runner"
)

func summary(counts map[classify.Verdict]int) runner.Summary {
	total := 0
	for _, n := range counts {
		total += n
	}
	return runner.Summary{
		Counts: counts,
		Total:  total,
		Leaks:  counts[classify.VerdictLeak] + counts[classify.VerdictHijack],
	}
}

func TestExitCode(t *testing.T) {
	cases := []struct {
		name   string
		counts map[classify.Verdict]int
		strict bool
		want   int
	}{
		{"all local", map[classify.Verdict]int{classify.VerdictLocal: 5}, false, 0},
		{"all error (unreachable)", map[classify.Verdict]int{classify.VerdictError: 5}, false, 2},
		{"leak present", map[classify.Verdict]int{classify.VerdictLocal: 4, classify.VerdictLeak: 1}, false, 1},
		{"hijack present", map[classify.Verdict]int{classify.VerdictHijack: 1}, false, 1},
		{"inconclusive, not strict", map[classify.Verdict]int{classify.VerdictLocal: 4, classify.VerdictInconclusive: 1}, false, 0},
		{"inconclusive, strict", map[classify.Verdict]int{classify.VerdictLocal: 4, classify.VerdictInconclusive: 1}, true, 1},
		{"errors but some local", map[classify.Verdict]int{classify.VerdictLocal: 3, classify.VerdictError: 2}, false, 0},
		{"leak outranks all-error edge", map[classify.Verdict]int{classify.VerdictLeak: 2}, false, 1},
	}
	for _, c := range cases {
		if got := exitCode(summary(c.counts), c.strict); got != c.want {
			t.Errorf("%s: exitCode = %d, want %d", c.name, got, c.want)
		}
	}
}
