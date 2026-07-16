package runner

import (
	"errors"
	"testing"

	"github.com/miekg/dns"

	"github.com/farrokhi/localzone-leaktest/internal/query"
)

func TestValidBaseline(t *testing.T) {
	cases := []struct {
		name string
		r    query.ProbeResult
		want bool
	}{
		{"nxdomain no answer", query.ProbeResult{RCode: dns.RcodeNameError}, true},
		{"transport error", query.ProbeResult{Err: errors.New("i/o timeout")}, false},
		{"servfail", query.ProbeResult{RCode: dns.RcodeServerFailure}, false},
		{"refused", query.ProbeResult{RCode: dns.RcodeRefused}, false},
		{"noerror with answer (rewrite)", query.ProbeResult{RCode: dns.RcodeSuccess, HasAnswer: true}, false},
		{"nxdomain with fabricated answer", query.ProbeResult{RCode: dns.RcodeNameError, HasAnswer: true}, false},
	}
	for _, c := range cases {
		if got := validBaseline(c.r); got != c.want {
			t.Errorf("%s: validBaseline = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestNeedsRD0 covers the trigger for the non-recursive follow-up probe: only a
// clean negative answer with no SOA warrants it.
func TestNeedsRD0(t *testing.T) {
	cases := []struct {
		name string
		r    query.ProbeResult
		want bool
	}{
		{"bare nxdomain", query.ProbeResult{RCode: dns.RcodeNameError}, true},
		{"bare noerror nodata", query.ProbeResult{RCode: dns.RcodeSuccess}, true},
		{"nxdomain with SOA", query.ProbeResult{RCode: dns.RcodeNameError, HasSOA: true}, false},
		{"answer present", query.ProbeResult{RCode: dns.RcodeSuccess, HasAnswer: true}, false},
		{"transport error", query.ProbeResult{Err: errors.New("i/o timeout")}, false},
		{"refused", query.ProbeResult{RCode: dns.RcodeRefused}, false},
	}
	for _, c := range cases {
		if got := needsRD0(c.r); got != c.want {
			t.Errorf("%s: needsRD0 = %v, want %v", c.name, got, c.want)
		}
	}
}
