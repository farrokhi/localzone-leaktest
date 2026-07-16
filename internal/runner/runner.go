// Package runner orchestrates a full test: it measures a recursion baseline,
// probes every selected zone with a bounded worker pool, classifies each
// answer, and aggregates the outcome into a summary.
package runner

import (
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/farrokhi/localzone-leaktest/internal/classify"
	"github.com/farrokhi/localzone-leaktest/internal/dataset"
	"github.com/farrokhi/localzone-leaktest/internal/query"
)

// Options configures a run.
type Options struct {
	Server      string   // resolver host, optionally host:port; empty means system default
	Port        int      // port used when Server has none; zero means 53
	Net         string   // "udp", "udp4", "udp6"
	Categories  []string // category filter; nil or {"all"} means everything
	Timeout     time.Duration
	Tries       int
	Concurrency int // parallel probes; zero means a sensible default
}

// Summary aggregates the outcome of a run.
type Summary struct {
	Resolver   string
	Baseline   time.Duration
	BaselineOK bool
	Counts     map[classify.Verdict]int
	Total      int
	Leaks      int // LEAK + HIJACK, the failing outcomes
}

// Report is the full result of a run.
type Report struct {
	Results []classify.Result
	Summary Summary
}

// Run probes the selected zones against the configured resolver.
func Run(opts Options) (*Report, error) {
	zones := dataset.Filter(dataset.Build(), opts.Categories)
	if len(zones) == 0 {
		return nil, fmt.Errorf("no zones selected for categories %v", opts.Categories)
	}

	q, err := query.New(query.Config{
		Server:  opts.Server,
		Port:    opts.Port,
		Net:     opts.Net,
		Timeout: opts.Timeout,
		Tries:   opts.Tries,
	})
	if err != nil {
		return nil, err
	}

	baseline, baselineOK := measureBaseline(q)

	results := probeAll(q, zones, baseline, opts.Concurrency)

	summary := Summary{
		Resolver:   q.Server(),
		Baseline:   baseline,
		BaselineOK: baselineOK,
		Counts:     map[classify.Verdict]int{},
		Total:      len(results),
	}
	for _, r := range results {
		summary.Counts[r.Verdict]++
	}
	summary.Leaks = summary.Counts[classify.VerdictLeak] + summary.Counts[classify.VerdictHijack]

	return &Report{Results: results, Summary: summary}, nil
}

// measureBaseline times a query that must recurse (a random label under .com).
// A failure or an anomalous control response yields a zero baseline, which the
// classifier treats as "unknown" and handles with absolute latency cutoffs.
func measureBaseline(q *query.Querier) (time.Duration, bool) {
	name, err := query.BaselineName()
	if err != nil {
		return 0, false
	}
	r := q.Query(name, query.DNSType(dataset.QTypeA))
	if !validBaseline(r) {
		return 0, false
	}
	return r.RTT, true
}

// validBaseline reports whether the control query produced the recursive
// negative answer we expect from a random label under a real TLD. Anything else
// (a transport error, SERVFAIL/REFUSED, or a rewritten answer from a hijacking
// resolver or captive portal) must not be trusted as a latency reference.
func validBaseline(r query.ProbeResult) bool {
	if r.Err != nil {
		return false
	}
	return r.RCode == dns.RcodeNameError && !r.HasAnswer
}

// probeAll probes every zone concurrently and returns results in dataset order.
func probeAll(q *query.Querier, zones []dataset.Zone, baseline time.Duration, concurrency int) []classify.Result {
	if concurrency < 1 {
		concurrency = 10
	}
	if concurrency > len(zones) {
		concurrency = len(zones)
	}

	results := make([]classify.Result, len(zones))
	jobs := make(chan int)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for i := range jobs {
			z := zones[i]
			name, err := query.ProbeName(z.Name)
			if err != nil {
				results[i] = classify.Result{Zone: z, Verdict: classify.VerdictError, Source: "probe name generation failed"}
				continue
			}
			r := q.Query(name, query.DNSType(z.QType))
			results[i] = classify.Classify(r, z, baseline)
		}
	}

	wg.Add(concurrency)
	for w := 0; w < concurrency; w++ {
		go worker()
	}
	for i := range zones {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	return results
}
