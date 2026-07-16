// Package classify turns a probe result into a per name verdict. Following the
// build spec (section 4), latency relative to a recursion baseline is the primary
// signal and the SOA source is confirmatory. A bare NXDOMAIN with no SOA and a
// low query time is a normal local answer; a root SOA is a locally synthesized
// aggressive-NSEC answer and is also local; only an AS112 per-zone SOA
// (prisoner.iana.org / blackhole / as112), or fabricated answer records, or a
// query time at the recursion baseline with nothing local to explain it, is a
// leak. The logic is pure so it can be tested against canned responses.
package classify

import (
	"regexp"
	"strings"
	"time"

	"github.com/farrokhi/localzone-leaktest/internal/dataset"
	"github.com/farrokhi/localzone-leaktest/internal/query"
)

// Verdict is the outcome for a single probed name.
type Verdict string

const (
	// VerdictLocal means the resolver kept the query local.
	VerdictLocal Verdict = "LOCAL"
	// VerdictLeak means the query reached the AS112 sink or the real authority.
	VerdictLeak Verdict = "LEAK"
	// VerdictHijack means an answer record was fabricated for a name that must not exist.
	VerdictHijack Verdict = "HIJACK"
	// VerdictInconclusive means the signals disagree or are ambiguous.
	VerdictInconclusive Verdict = "INCONCLUSIVE"
	// VerdictError means the probe failed or returned an anomalous RCODE.
	VerdictError Verdict = "ERROR"
)

// Result pairs a probe with its verdict and a short human readable source note.
type Result struct {
	Zone    dataset.Zone
	Probe   query.ProbeResult
	Verdict Verdict
	Source  string
}

// leakSOARe is the unambiguous AS112 leak fingerprint: the sink that answers
// leaked private reverse queries. See the build spec, section 4. Note that
// root-servers.net and verisign are deliberately NOT here: a root SOA is a
// locally synthesized answer, not a leak.
var leakSOARe = regexp.MustCompile(`(?i)prisoner\.iana\.org|blackhole|as112`)

// ambiguousSOARe matches parent-operator and RIR sources. These appear both on a
// genuine leak to the parent and on an answer synthesized locally from the
// parent's NSEC, so they do not decide the verdict on their own.
var ambiguousSOARe = regexp.MustCompile(`(?i)in-addr-servers\.arpa|ip6-servers\.arpa|iana\.org|arin|ripe|apnic|lacnic|afrinic`)

// localPolicyEDE lists Extended DNS Error codes (RFC 8914) that indicate the
// answer was produced by local policy or synthesized locally. Supporting
// evidence for a local classification, never required.
var localPolicyEDE = map[int]bool{
	4:  true, // Forged Answer
	15: true, // Blocked
	16: true, // Censored
	17: true, // Filtered
	18: true, // Prohibited
	29: true, // Synthesized (aggressive NSEC, RFC 8198)
}

type soaBucket int

const (
	soaNone      soaBucket = iota // no SOA in the authority section
	soaLocal                      // root SOA, or a synthetic / local mname
	soaLeak                       // AS112 fingerprint
	soaAmbiguous                  // parent-operator / RIR source
)

type latBucket int

const (
	latMiddle latBucket = iota // between the local and leak regimes, or no baseline
	latLocal                   // far below the recursion baseline
	latLeak                    // at or above the recursion baseline
)

// Classify returns the verdict for one probe result, given the recursion
// baseline used as the primary latency reference.
func Classify(r query.ProbeResult, zone dataset.Zone, baseline time.Duration) Result {
	res := Result{Zone: zone, Probe: r}

	if r.Err != nil {
		res.Verdict = VerdictError
		res.Source = "query failed: " + errBrief(r.Err)
		return res
	}

	// Anything other than a clean NXDOMAIN or NOERROR is an anomaly.
	switch r.RCode {
	case 0, 3: // NOERROR, NXDOMAIN
	default:
		res.Verdict = VerdictError
		res.Source = "unexpected RCODE " + rcodeName(r)
		return res
	}

	// Fabricated answers for a name that cannot exist. resolver.arpa answered
	// with SVCB/HTTPS is by design (DDR) and stays informational.
	if r.HasAnswer {
		if zone.Informational && onlySVCB(r.Answers) {
			res.Verdict = VerdictLocal
			res.Source = "DDR SVCB answer (informational)"
			return res
		}
		res.Verdict = VerdictHijack
		res.Source = "answered " + r.Answers[0]
		return res
	}

	soa := classifySOA(r)
	lat := classifyLatency(r.RTT, baseline)
	// A local-policy or synthesized EDE is the strongest local signal when no
	// AS112 fingerprint is present; it supports LOCAL but is never required.
	localEDE := r.EDECode >= 0 && localPolicyEDE[r.EDECode]

	switch soa {
	case soaLeak:
		// The AS112 fingerprint is unambiguous and outranks an EDE.
		res.Verdict = VerdictLeak
		res.Source = "leaked to AS112 (" + trimDot(r.SOAMName) + ")"
	case soaLocal:
		res.Verdict = VerdictLocal
		if trimDot(r.SOAOwner) == "" {
			res.Source = "served locally (root SOA)"
		} else {
			res.Source = "served locally (SOA " + trimDot(r.SOAMName) + ")"
		}
	case soaAmbiguous:
		if localEDE {
			res.Verdict, res.Source = VerdictLocal, "served locally (local-policy EDE)"
		} else {
			res.Verdict, res.Source = ambiguousVerdict(lat, r)
		}
	case soaNone:
		if localEDE {
			res.Verdict, res.Source = VerdictLocal, "served locally (no SOA, local-policy EDE)"
		} else {
			res.Verdict, res.Source = noSOAVerdict(lat)
		}
	}

	return res
}

// classifySOA sorts the authority SOA into one of the four buckets. Leak is
// checked first so that prisoner.iana.org is a leak rather than an ambiguous
// iana.org match.
func classifySOA(r query.ProbeResult) soaBucket {
	if !r.HasSOA {
		return soaNone
	}
	mname := strings.ToLower(r.SOAMName)
	if leakSOARe.MatchString(mname) {
		return soaLeak
	}
	// We deliberately do not treat "SOA owner == queried zone apex with AA=1" as
	// a leak. An AS112-direct answer and a compliant local RFC 6303 empty-zone
	// resolver both look exactly like that, so the owner cannot distinguish them.
	// The mname fingerprint above is the only reliable AS112 signal.
	if trimDot(r.SOAOwner) == "" { // owner is the root: aggressive-NSEC local answer
		return soaLocal
	}
	if ambiguousSOARe.MatchString(mname) {
		return soaAmbiguous
	}
	// A synthetic or local mname (localhost., *.invalid., the resolver's own
	// hostname, and the like).
	return soaLocal
}

// classifyLatency places a query time in the local, leak, or middle regime
// relative to the recursion baseline. A few milliseconds is treated as clearly
// local regardless of baseline, to protect the common fast local answer when the
// baseline is small.
func classifyLatency(rtt, baseline time.Duration) latBucket {
	const clearlyLocal = 3 * time.Millisecond
	if rtt <= clearlyLocal {
		return latLocal
	}
	if baseline > 0 {
		if rtt*2 <= baseline { // <= 50% of baseline: far below
			return latLocal
		}
		if rtt*5 >= baseline*4 { // >= 80% of baseline: at or above
			return latLeak
		}
		return latMiddle
	}
	// No usable baseline: fall back to conservative absolute cutoffs.
	if rtt >= 30*time.Millisecond {
		return latLeak
	}
	return latMiddle
}

// noSOAVerdict decides a bare NXDOMAIN (no authority SOA) from latency alone.
func noSOAVerdict(lat latBucket) (Verdict, string) {
	switch lat {
	case latLocal:
		return VerdictLocal, "served locally (no SOA, low query time)"
	case latLeak:
		return VerdictLeak, "no SOA, query time at recursion baseline"
	default:
		return VerdictInconclusive, "no SOA, mid-range query time"
	}
}

// ambiguousVerdict decides a parent-operator SOA from latency.
func ambiguousVerdict(lat latBucket, r query.ProbeResult) (Verdict, string) {
	src := trimDot(r.SOAMName)
	switch lat {
	case latLocal:
		return VerdictLocal, "served locally (parent SOA " + src + ", low query time)"
	case latLeak:
		return VerdictLeak, "leaked to parent operator (" + src + ")"
	default:
		return VerdictInconclusive, "ambiguous parent SOA (" + src + "), mid-range query time"
	}
}

func onlySVCB(answers []string) bool {
	if len(answers) == 0 {
		return false
	}
	for _, a := range answers {
		if !strings.HasPrefix(a, "SVCB") && !strings.HasPrefix(a, "HTTPS") {
			return false
		}
	}
	return true
}

func trimDot(s string) string { return strings.TrimSuffix(s, ".") }

func rcodeName(r query.ProbeResult) string {
	if r.RCodeText != "" {
		return r.RCodeText
	}
	return "unknown"
}

func errBrief(err error) string {
	s := err.Error()
	if strings.Contains(s, "timeout") || strings.Contains(s, "i/o timeout") {
		return "timeout"
	}
	return s
}
