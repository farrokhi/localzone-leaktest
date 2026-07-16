// Package classify turns a probe result into a per name verdict. The authority
// SOA is the deciding evidence: RFC 2308 (sections 3 and 5) guarantees every
// recursed negative carries its source SOA, so a bare no-SOA negative is a
// local policy answer, a root or synthetic SOA is local, and an AS112 or
// parent/RIR/ICANN SOA is a leak. An optional RD=0 follow-up refines the
// no-SOA case. Query time never decides a verdict.
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
	VerdictLocal  Verdict = "LOCAL"
	VerdictLeak   Verdict = "LEAK"
	VerdictHijack Verdict = "HIJACK"
	// VerdictInconclusive is no longer produced by the classifier; kept so
	// reports and the --strict exit path remain stable.
	VerdictInconclusive Verdict = "INCONCLUSIVE"
	VerdictError        Verdict = "ERROR"
)

// Result pairs a probe with its verdict and a short human readable source note.
type Result struct {
	Zone    dataset.Zone
	Probe   query.ProbeResult
	Verdict Verdict
	Source  string
	// RD0 is one of the RD0* constants, or "" when the follow-up was not sent.
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

// leakSOARe is the AS112 sink fingerprint (RFC 7534, RFC 7535). root-servers.net
// is deliberately absent: a root SOA is a local answer, not a leak.
var leakSOARe = regexp.MustCompile(`(?i)prisoner\.iana\.org|blackhole|as112`)

// parentSOARe matches parent-operator, RIR, and ICANN sources, which only
// originate from the public DNS and mark a leak even when answered from cache:
// the cache was seeded by this resolver leaking the zone.
var parentSOARe = regexp.MustCompile(`(?i)in-addr-servers\.arpa|ip6-servers\.arpa|iana\.org|icann\.org|arin|ripe|apnic|lacnic|afrinic`)

// localPolicyEDE lists RFC 8914 codes that mark an answer as locally produced.
// Supporting evidence only; never decides a verdict.
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

// Classify returns the verdict for one probe result. rd0 is the optional RD=0
// follow-up, nil when not sent.
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

	// resolver.arpa answering SVCB is by design (DDR), not a hijack.
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

	localEDE := r.EDECode >= 0 && localPolicyEDE[r.EDECode]

	switch classifySOA(r) {
	case soaLeak:
		res.Verdict = VerdictLeak
		res.Source = "leaked to AS112 (" + trimDot(r.SOAMName) + ")"
	case soaLocal:
		res.Verdict = VerdictLocal
		if trimDot(r.SOAOwner) == "" {
			// Synthesized from cached root NSEC (RFC 8198) or fetched from the
			// root; no registry mandates local service for these names.
			res.Source = "root-derived answer (root SOA, synthesized or queried)"
		} else {
			res.Source = "served locally (SOA " + trimDot(r.SOAMName) + ")"
		}
	case soaParent:
		res.Verdict = VerdictLeak
		res.Source = "leaked to " + leakTarget(r.SOAMName) + " (" + trimDot(r.SOAMName) + ")"
		if localEDE {
			res.Source += ", possibly from cache"
		}
	case soaNone:
		res.Verdict = VerdictLocal
		res.Source = "local policy answer (no SOA)"
		if localEDE {
			res.Source = "local policy answer (no SOA, local-policy EDE)"
		}
		applyRD0(&res, rd0)
	}

	return res
}

// applyRD0 folds the RD=0 follow-up into a no-SOA result. A refusal proves
// nothing, since refusing RD=0 is standard cache-snooping protection.
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

func rd0Outcome(r query.ProbeResult) string {
	switch {
	case r.Err != nil:
		return RD0Error
	case r.RCode == 3 && !r.HasAnswer: // NXDOMAIN
		switch classifySOA(r) {
		case soaLeak, soaParent:
			return RD0Leak
		default:
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
	// An AS112-direct answer and a local RFC 6303 empty zone look identical
	// (zone-apex SOA owner, AA=1), so only the mname fingerprint is trusted.
	if trimDot(r.SOAOwner) == "" { // owner is the root
		return soaLocal
	}
	if parentSOARe.MatchString(mname) {
		return soaParent
	}
	// Synthetic or local mname (localhost., the resolver's own hostname, ...).
	return soaLocal
}

// leakTarget names where a leaked query ended up; ICANN's empty zones are the
// zone's own authority acting as a sink, not a parent operator.
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
