package classify

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/farrokhi/localzone-leaktest/internal/dataset"
	"github.com/farrokhi/localzone-leaktest/internal/query"
)

const baseline = 20 * time.Millisecond

// loadFixture reads a committed wire format response and reduces it to a
// ProbeResult, so the classifier is exercised without any network access.
func loadFixture(t *testing.T, name string, rtt time.Duration) query.ProbeResult {
	t.Helper()
	path := filepath.Join("..", "..", "tests", "fixtures", name+".bin")
	wire, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	m := new(dns.Msg)
	if err := m.Unpack(wire); err != nil {
		t.Fatalf("unpacking fixture %s: %v", name, err)
	}
	qname, qtype := "", uint16(dns.TypePTR)
	if len(m.Question) > 0 {
		qname, qtype = m.Question[0].Name, m.Question[0].Qtype
	}
	return query.ResultFromMsg(m, qname, qtype, rtt, nil)
}

var (
	reverseZone = dataset.Zone{Name: "168.192.in-addr.arpa", Category: dataset.CategoryRFC1918, QType: dataset.QTypePTR}
	as112Zone   = dataset.Zone{Name: "168.192.in-addr.arpa", Category: dataset.CategoryRFC1918, QType: dataset.QTypePTR}
	corpZone    = dataset.Zone{Name: "corp", Category: dataset.CategorySpecial, QType: dataset.QTypeA}
	parentZone  = dataset.Zone{Name: "0.in-addr.arpa", Category: dataset.CategoryIPv4Special, QType: dataset.QTypePTR}
)

// TestFixtureVerdicts drives the four canonical wire shapes from spec section 13.
func TestFixtureVerdicts(t *testing.T) {
	cases := []struct {
		fixture string
		zone    dataset.Zone
		rtt     time.Duration
		want    Verdict
	}{
		// Bare NXDOMAIN, no SOA. Local when fast, leak when at the baseline.
		{"local-bare", reverseZone, 1 * time.Millisecond, VerdictLocal},
		{"local-bare", reverseZone, 20 * time.Millisecond, VerdictLocal}, // EDE 29 keeps it local
		// Root SOA via aggressive NSEC is local regardless of latency.
		{"local-root-soa", corpZone, 19 * time.Millisecond, VerdictLocal},
		// AS112 prisoner.iana.org fingerprint is a leak regardless of latency.
		{"as112-leak", as112Zone, 1 * time.Millisecond, VerdictLeak},
		{"as112-leak", as112Zone, 20 * time.Millisecond, VerdictLeak},
		// Hijack: fabricated answer record.
		{"hijack", corpZone, 15 * time.Millisecond, VerdictHijack},
	}
	for _, c := range cases {
		r := loadFixture(t, c.fixture, c.rtt)
		got := Classify(r, c.zone, baseline)
		if got.Verdict != c.want {
			t.Errorf("%s @ %v: verdict = %s (%s), want %s", c.fixture, c.rtt, got.Verdict, got.Source, c.want)
		}
	}
}

// TestRootSOAIsLocal is the explicit regression guard for the reported bug: a
// root SOA must never be classified as a leak.
func TestRootSOAIsLocal(t *testing.T) {
	r := loadFixture(t, "local-root-soa", 25*time.Millisecond) // even above baseline
	got := Classify(r, corpZone, baseline)
	if got.Verdict != VerdictLocal {
		t.Fatalf("root SOA verdict = %s (%s), want LOCAL", got.Verdict, got.Source)
	}
	if !strings.Contains(got.Source, "root SOA") {
		t.Errorf("source %q should mention root SOA", got.Source)
	}
}

// TestAS112LeakSource confirms the leak names the AS112 sink.
func TestAS112LeakSource(t *testing.T) {
	r := loadFixture(t, "as112-leak", 5*time.Millisecond)
	got := Classify(r, as112Zone, baseline)
	if got.Verdict != VerdictLeak {
		t.Fatalf("verdict = %s, want LEAK", got.Verdict)
	}
	if !strings.Contains(got.Source, "prisoner.iana.org") {
		t.Errorf("leak source %q should name prisoner.iana.org", got.Source)
	}
}

// TestAmbiguousParent covers the parent-operator SOA resolved by latency.
func TestAmbiguousParent(t *testing.T) {
	cases := []struct {
		rtt  time.Duration
		want Verdict
	}{
		{1 * time.Millisecond, VerdictLocal},         // far below baseline
		{12 * time.Millisecond, VerdictInconclusive}, // mid-range
		{20 * time.Millisecond, VerdictLeak},         // at baseline
	}
	for _, c := range cases {
		r := loadFixture(t, "ambiguous-parent", c.rtt)
		got := Classify(r, parentZone, baseline)
		if got.Verdict != c.want {
			t.Errorf("ambiguous @ %v: verdict = %s (%s), want %s", c.rtt, got.Verdict, got.Source, c.want)
		}
	}
}

// TestNoSOALatency covers a bare NXDOMAIN with no EDE, decided by latency alone.
func TestNoSOALatency(t *testing.T) {
	cases := []struct {
		rtt  time.Duration
		want Verdict
	}{
		{1 * time.Millisecond, VerdictLocal},
		{12 * time.Millisecond, VerdictInconclusive},
		{20 * time.Millisecond, VerdictLeak},
	}
	for _, c := range cases {
		r := query.ProbeResult{EDECode: -1, RCode: dns.RcodeNameError, RTT: c.rtt}
		got := Classify(r, corpZone, baseline)
		if got.Verdict != c.want {
			t.Errorf("no-SOA @ %v: verdict = %s (%s), want %s", c.rtt, got.Verdict, got.Source, c.want)
		}
	}
}

// TestLocalPolicyEDENudge: a mid-range no-SOA answer that would be inconclusive
// is nudged to LOCAL by a synthesized/local-policy EDE.
func TestLocalPolicyEDENudge(t *testing.T) {
	r := query.ProbeResult{EDECode: 29, EDEText: "Synthesized", RCode: dns.RcodeNameError, RTT: 12 * time.Millisecond}
	got := Classify(r, corpZone, baseline)
	if got.Verdict != VerdictLocal {
		t.Errorf("EDE nudge: verdict = %s (%s), want LOCAL", got.Verdict, got.Source)
	}
}

func TestErrorCases(t *testing.T) {
	got := Classify(query.ProbeResult{EDECode: -1, Err: errors.New("read udp: i/o timeout")}, corpZone, baseline)
	if got.Verdict != VerdictError {
		t.Errorf("timeout: verdict = %s, want ERROR", got.Verdict)
	}
	got = Classify(query.ProbeResult{EDECode: -1, RCode: dns.RcodeServerFailure, RCodeText: "SERVFAIL"}, corpZone, baseline)
	if got.Verdict != VerdictError {
		t.Errorf("servfail: verdict = %s, want ERROR", got.Verdict)
	}
}

func TestInformationalSVCB(t *testing.T) {
	zone := dataset.Zone{Name: "resolver.arpa", Informational: true}
	r := query.ProbeResult{EDECode: -1, RCode: dns.RcodeSuccess, Answers: []string{"SVCB ."}, HasAnswer: true}
	if got := Classify(r, zone, baseline); got.Verdict != VerdictLocal {
		t.Errorf("informational SVCB: verdict = %s, want LOCAL (not HIJACK)", got.Verdict)
	}
}

// TestSyntheticMNameIsLocal covers a resolver's own synthetic negative-caching
// SOA (for example AdGuard's fake-for-negative-caching host), which is local.
func TestSyntheticMNameIsLocal(t *testing.T) {
	r := query.ProbeResult{
		EDECode: -1, RCode: dns.RcodeNameError, RTT: 2 * time.Millisecond,
		HasSOA: true, SOAOwner: "probe-x.10.in-addr.arpa.", SOAMName: "fake-for-negative-caching.adguard.com.",
	}
	if got := Classify(r, reverseZone, baseline); got.Verdict != VerdictLocal {
		t.Errorf("synthetic mname: verdict = %s (%s), want LOCAL", got.Verdict, got.Source)
	}
}
