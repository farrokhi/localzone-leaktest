// Package classify turns a probe result into a per name verdict. The SOA in
// the authority section is the deciding evidence. RFC 2308 section 3 requires
// authoritative servers to include the zone SOA on negative answers, and
// section 5 requires a resolver answering from cache to add the cached SOA
// back, so every genuinely recursed negative carries an SOA: a bare NXDOMAIN
// with no SOA is a resolver policy answer, which is local. A root SOA is a
// locally synthesized aggressive-NSEC answer and is also local. An AS112
// per-zone SOA (prisoner.iana.org / blackhole / as112) or a parent-operator /
// RIR / ICANN SOA (z.arin.net, ip6-servers.arpa, sns.dns.icann.org, ...) is a
// leak: neither can originate from a compliant RFC 6303 local zone. Fabricated
// answer records are a hijack. An optional non-recursive (RD=0) follow-up probe
// refines the no-SOA case: an answer proves local zone data, and an answer
// carrying a public-source SOA exposes leaked data sitting in the cache. Query
// time never decides a verdict. The logic is pure so it can be tested against
// canned responses.
package classify

import (
	"regexp"
	"strings"

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
	// VerdictInconclusive is no longer produced by the SOA-only classifier. It
	// is kept so reports and the --strict exit path remain stable.
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
	// RD0 summarizes the optional non-recursive follow-up probe; one of the
	// RD0* constants, or "" when the probe was not sent.
	RD0 string
}

// RD0 outcome values, surfaced verbatim in verbose and JSON output.
const (
	RD0Confirmed = "confirmed" // answered from local zone data
	RD0Leak      = "leak"      // carried a public-source SOA snooped from cache
	RD0Refused   = "refused"   // refused the non-recursive query
	RD0Error     = "error"     // transport error or timeout
	RD0Other     = "other"     // any other response shape; proves nothing
)

// leakSOARe is the unambiguous AS112 leak fingerprint: the sink that answers
// leaked private reverse queries (RFC 7534, RFC 7535). Note that
// root-servers.net and verisign are deliberately NOT here: a root SOA is a
// locally synthesized answer, not a leak.
var leakSOARe = regexp.MustCompile(`(?i)prisoner\.iana\.org|blackhole|as112`)

// parentSOARe matches parent-operator, RIR, and IANA/ICANN sources. These only
// originate from the public DNS: a compliant RFC 6303 local zone never emits
// one, so they mark a leak. icann.org covers sns.dns.icann.org, the SOA mname
// of the empty zones ICANN serves on a/b/c.iana-servers.net (for example the
// 100.64.0.0/10 reverse). The answer may have been synthesized from cached NSEC
// (RFC 8198) rather than forwarded live, but that cache was itself seeded by
// this resolver querying the public servers, so the zone leaks either way.
var parentSOARe = regexp.MustCompile(`(?i)in-addr-servers\.arpa|ip6-servers\.arpa|iana\.org|icann\.org|arin|ripe|apnic|lacnic|afrinic`)

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
	soaNone   soaBucket = iota // no SOA in the authority section
	soaLocal                   // root SOA, or a synthetic / local mname
	soaLeak                    // AS112 fingerprint
	soaParent                  // parent-operator / RIR source
)

// Classify returns the verdict for one probe result. rd0 is the optional
// non-recursive follow-up probe sent when the primary answer carried no SOA,
// or nil when it was not sent.
func Classify(r query.ProbeResult, rd0 *query.ProbeResult, zone dataset.Zone) Result {
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

	// A local-policy or synthesized EDE (RFC 8914) is supporting evidence only;
	// it enriches the source text but never decides a verdict.
	localEDE := r.EDECode >= 0 && localPolicyEDE[r.EDECode]

	switch classifySOA(r) {
	case soaLeak:
		res.Verdict = VerdictLeak
		res.Source = "leaked to AS112 (" + trimDot(r.SOAMName) + ")"
	case soaLocal:
		res.Verdict = VerdictLocal
		if trimDot(r.SOAOwner) == "" {
			// Root SOA: synthesized from cached root NSEC (RFC 8198) or fetched
			// from the root. Indistinguishable from outside, but with QNAME
			// minimization at most the bare TLD label leaves the resolver, and
			// no registry mandates local service for these names.
			res.Source = "root-derived answer (root SOA, synthesized or queried)"
		} else {
			res.Source = "served locally (SOA " + trimDot(r.SOAMName) + ")"
		}
	case soaParent:
		// Always a leak: only the public DNS produces this SOA. The answer may
		// have come from the resolver's cache this time, which changes nothing
		// about where the data originated.
		res.Verdict = VerdictLeak
		res.Source = "leaked to " + leakTarget(r.SOAMName) + " (" + trimDot(r.SOAMName) + ")"
		if localEDE {
			res.Source += ", possibly from cache"
		}
	case soaNone:
		// A recursed negative always carries the authority SOA (RFC 2308
		// section 3 from the authority, section 5 from a cache), so its absence
		// means the resolver synthesized this answer by policy.
		res.Verdict = VerdictLocal
		res.Source = "local policy answer (no SOA)"
		if localEDE {
			res.Source = "local policy answer (no SOA, local-policy EDE)"
		}
		applyRD0(&res, rd0)
	}

	return res
}

// applyRD0 folds the non-recursive follow-up probe into a no-SOA result. An
// answered RD=0 probe for a fresh random name proves the resolver holds the
// zone data itself; one carrying a public-source SOA is leaked data snooped
// from the cache, which flips the verdict. A refusal proves nothing, since
// refusing RD=0 is standard cache-snooping protection.
func applyRD0(res *Result, rd0 *query.ProbeResult) {
	if rd0 == nil {
		return
	}
	res.RD0 = rd0Outcome(*rd0)
	switch res.RD0 {
	case RD0Confirmed:
		res.Source += ", confirmed by non-recursive query"
	case RD0Leak:
		res.Verdict = VerdictLeak
		res.Source = "leaked earlier, found in cache via non-recursive query (" + trimDot(rd0.SOAMName) + ")"
	}
}

// rd0Outcome buckets the RD=0 probe response.
func rd0Outcome(r query.ProbeResult) string {
	switch {
	case r.Err != nil:
		return RD0Error
	case r.RCode == 3 && !r.HasAnswer: // NXDOMAIN
		switch classifySOA(r) {
		case soaLeak, soaParent:
			return RD0Leak
		default: // no SOA, or the zone's own / synthetic SOA: local zone data
			return RD0Confirmed
		}
	case r.RCode == 5: // REFUSED
		return RD0Refused
	default:
		return RD0Other
	}
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
	if parentSOARe.MatchString(mname) {
		return soaParent
	}
	// A synthetic or local mname (localhost., *.invalid., the resolver's own
	// hostname, and the like).
	return soaLocal
}

// leakTarget names where a leaked query ended up. ICANN serves some special
// zones empty on the iana-servers.net set (SOA mname sns.dns.icann.org), which
// is the zone's own authority acting as a sink, not a parent operator.
func leakTarget(mname string) string {
	if strings.Contains(strings.ToLower(mname), "icann.org") {
		return "IANA empty zone"
	}
	return "parent operator"
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
