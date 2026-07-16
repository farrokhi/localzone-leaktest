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

// TestFixtureVerdicts drives the canonical wire shapes. Query time never
// decides a verdict, so each shape classifies the same at any RTT.
func TestFixtureVerdicts(t *testing.T) {
	cases := []struct {
		fixture string
		zone    dataset.Zone
		rtt     time.Duration
		want    Verdict
	}{
		// Bare NXDOMAIN, no SOA: a local policy answer at any query time.
		{"local-bare", reverseZone, 1 * time.Millisecond, VerdictLocal},
		{"local-bare", reverseZone, 31 * time.Millisecond, VerdictLocal},
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
		got := Classify(r, nil, c.zone)
		if got.Verdict != c.want {
			t.Errorf("%s @ %v: verdict = %s (%s), want %s", c.fixture, c.rtt, got.Verdict, got.Source, c.want)
		}
	}
}

// TestRootSOAIsLocal is the explicit regression guard for the reported bug: a
// root SOA must never be classified as a leak.
func TestRootSOAIsLocal(t *testing.T) {
	r := loadFixture(t, "local-root-soa", 25*time.Millisecond)
	got := Classify(r, nil, corpZone)
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
	got := Classify(r, nil, as112Zone)
	if got.Verdict != VerdictLeak {
		t.Fatalf("verdict = %s, want LEAK", got.Verdict)
	}
	if !strings.Contains(got.Source, "prisoner.iana.org") {
		t.Errorf("leak source %q should name prisoner.iana.org", got.Source)
	}
}

// TestParentSOAIsLeak: a parent-operator / RIR SOA is a leak at any query time,
// since only the public DNS produces it.
func TestParentSOAIsLeak(t *testing.T) {
	for _, rtt := range []time.Duration{1 * time.Millisecond, 12 * time.Millisecond, 20 * time.Millisecond} {
		r := loadFixture(t, "ambiguous-parent", rtt)
		got := Classify(r, nil, parentZone)
		if got.Verdict != VerdictLeak {
			t.Errorf("parent SOA @ %v: verdict = %s (%s), want LEAK", rtt, got.Verdict, got.Source)
		}
	}
	// A synthesized EDE marks the answer as cache-derived in the source text.
	r := loadFixture(t, "ambiguous-parent", 1*time.Millisecond)
	r.EDECode, r.EDEText = 29, "Synthesized"
	if got := Classify(r, nil, parentZone); !strings.Contains(got.Source, "possibly from cache") {
		t.Errorf("synthesized parent SOA source %q should note the cache path", got.Source)
	}
}

// TestICANNEmptyZoneIsLeak: ICANN serves some special zones empty on the
// iana-servers.net set with SOA mname sns.dns.icann.org (for example the CGNAT
// 100.64.0.0/10 reverse). That mname matches neither the AS112 nor the RIR
// fingerprints, and must not fall through to the local synthetic-mname bucket.
func TestICANNEmptyZoneIsLeak(t *testing.T) {
	zone := dataset.Zone{Name: "64.100.in-addr.arpa", Category: dataset.CategoryIPv4Special, QType: dataset.QTypePTR}
	r := query.ProbeResult{
		EDECode: -1, RCode: dns.RcodeNameError, RTT: 15 * time.Millisecond,
		HasSOA: true, SOAOwner: "64.100.in-addr.arpa.", SOAMName: "sns.dns.icann.org.",
	}
	got := Classify(r, nil, zone)
	if got.Verdict != VerdictLeak {
		t.Fatalf("icann empty zone: verdict = %s (%s), want LEAK", got.Verdict, got.Source)
	}
	if !strings.Contains(got.Source, "sns.dns.icann.org") {
		t.Errorf("source %q should name sns.dns.icann.org", got.Source)
	}
}

// TestNoSOAIsLocal is the regression guard for the verdict flapping reported
// against 8.8.8.8: a bare no-SOA negative answer is a local policy answer at
// any query time (RFC 2308 requires recursed negatives to carry an SOA).
func TestNoSOAIsLocal(t *testing.T) {
	for _, rtt := range []time.Duration{1 * time.Millisecond, 12 * time.Millisecond, 31 * time.Millisecond} {
		r := query.ProbeResult{EDECode: -1, RCode: dns.RcodeNameError, RTT: rtt}
		got := Classify(r, nil, corpZone)
		if got.Verdict != VerdictLocal {
			t.Errorf("no-SOA @ %v: verdict = %s (%s), want LOCAL", rtt, got.Verdict, got.Source)
		}
	}
}

// TestLocalPolicyEDE: a synthesized/local-policy EDE is reflected in the source
// text of a no-SOA local answer.
func TestLocalPolicyEDE(t *testing.T) {
	r := query.ProbeResult{EDECode: 29, EDEText: "Synthesized", RCode: dns.RcodeNameError, RTT: 12 * time.Millisecond}
	got := Classify(r, nil, corpZone)
	if got.Verdict != VerdictLocal {
		t.Fatalf("EDE: verdict = %s (%s), want LOCAL", got.Verdict, got.Source)
	}
	if !strings.Contains(got.Source, "EDE") {
		t.Errorf("source %q should mention the EDE", got.Source)
	}
}

// TestRD0Outcomes covers the non-recursive follow-up: an answered probe
// confirms local data, a public-source SOA exposes leaked data in the cache,
// and a refusal changes nothing.
func TestRD0Outcomes(t *testing.T) {
	noSOA := query.ProbeResult{EDECode: -1, RCode: dns.RcodeNameError, RTT: 12 * time.Millisecond}

	confirmed := &query.ProbeResult{EDECode: -1, RCode: dns.RcodeNameError, AA: true,
		HasSOA: true, SOAOwner: "168.192.in-addr.arpa.", SOAMName: "localhost."}
	got := Classify(noSOA, confirmed, reverseZone)
	if got.Verdict != VerdictLocal || !strings.Contains(got.Source, "confirmed by non-recursive query") {
		t.Errorf("rd0 confirmed: verdict = %s (%s), want LOCAL with confirmation", got.Verdict, got.Source)
	}
	if got.RD0 != "confirmed" {
		t.Errorf("rd0 = %q, want confirmed", got.RD0)
	}

	snooped := &query.ProbeResult{EDECode: -1, RCode: dns.RcodeNameError,
		HasSOA: true, SOAOwner: "168.192.in-addr.arpa.", SOAMName: "prisoner.iana.org."}
	got = Classify(noSOA, snooped, reverseZone)
	if got.Verdict != VerdictLeak || !strings.Contains(got.Source, "prisoner.iana.org") {
		t.Errorf("rd0 snooped leak: verdict = %s (%s), want LEAK naming the sink", got.Verdict, got.Source)
	}
	if got.RD0 != "leak" {
		t.Errorf("rd0 = %q, want leak", got.RD0)
	}

	refused := &query.ProbeResult{EDECode: -1, RCode: dns.RcodeRefused}
	got = Classify(noSOA, refused, reverseZone)
	if got.Verdict != VerdictLocal || strings.Contains(got.Source, "confirmed") {
		t.Errorf("rd0 refused: verdict = %s (%s), want plain LOCAL", got.Verdict, got.Source)
	}
	if got.RD0 != "refused" {
		t.Errorf("rd0 = %q, want refused", got.RD0)
	}
}

func TestErrorCases(t *testing.T) {
	got := Classify(query.ProbeResult{EDECode: -1, Err: errors.New("read udp: i/o timeout")}, nil, corpZone)
	if got.Verdict != VerdictError {
		t.Errorf("timeout: verdict = %s, want ERROR", got.Verdict)
	}
	got = Classify(query.ProbeResult{EDECode: -1, RCode: dns.RcodeServerFailure, RCodeText: "SERVFAIL"}, nil, corpZone)
	if got.Verdict != VerdictError {
		t.Errorf("servfail: verdict = %s, want ERROR", got.Verdict)
	}
}

func TestInformationalSVCB(t *testing.T) {
	zone := dataset.Zone{Name: "resolver.arpa", Informational: true}
	r := query.ProbeResult{EDECode: -1, RCode: dns.RcodeSuccess, Answers: []string{"SVCB ."}, HasAnswer: true}
	if got := Classify(r, nil, zone); got.Verdict != VerdictLocal {
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
	if got := Classify(r, nil, reverseZone); got.Verdict != VerdictLocal {
		t.Errorf("synthetic mname: verdict = %s (%s), want LOCAL", got.Verdict, got.Source)
	}
}
