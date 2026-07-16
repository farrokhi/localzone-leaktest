package report

import (
	"encoding/json"
	"io"

	"github.com/farrokhi/localzone-leaktest/internal/classify"
	"github.com/farrokhi/localzone-leaktest/internal/runner"
)

// jsonResult is one name's result in JSON form.
type jsonResult struct {
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	RFC         string   `json:"rfc"`
	AS112       bool     `json:"as112"`
	Verdict     string   `json:"verdict"`
	RCode       string   `json:"rcode"`
	AA          bool     `json:"aa"`
	QueryTimeMS int64    `json:"query_time_ms"`
	SOAOwner    string   `json:"soa_owner"`
	SOAMName    string   `json:"soa_mname"`
	EDE         *jsonEDE `json:"ede"`
	// RD0 is the non-recursive follow-up outcome; empty when it was not probed.
	RD0    string `json:"rd0,omitempty"`
	Source string `json:"source"`
}

type jsonEDE struct {
	Code int    `json:"code"`
	Text string `json:"text"`
}

type jsonSummary struct {
	Resolver   string         `json:"resolver"`
	BaselineMS *int64         `json:"baseline_ms"`
	Total      int            `json:"total"`
	Counts     map[string]int `json:"counts"`
	Leaks      int            `json:"leaks"`
}

type jsonReport struct {
	Results []jsonResult `json:"results"`
	Summary jsonSummary  `json:"summary"`
}

// JSON writes the report as a single JSON object to w.
func JSON(w io.Writer, rep *runner.Report) error {
	out := jsonReport{
		Results: make([]jsonResult, 0, len(rep.Results)),
		Summary: toJSONSummary(rep.Summary),
	}
	for _, r := range rep.Results {
		out.Results = append(out.Results, toJSONResult(r))
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func toJSONResult(r classify.Result) jsonResult {
	jr := jsonResult{
		Name:        r.Zone.Name,
		Category:    r.Zone.Category,
		RFC:         r.Zone.RFC,
		AS112:       r.Zone.AS112,
		Verdict:     string(r.Verdict),
		RCode:       r.Probe.RCodeText,
		AA:          r.Probe.AA,
		QueryTimeMS: queryTimeMS(r),
		SOAOwner:    r.Probe.SOAOwner,
		SOAMName:    r.Probe.SOAMName,
		RD0:         r.RD0,
		Source:      r.Source,
	}
	if r.Probe.EDECode >= 0 {
		jr.EDE = &jsonEDE{Code: r.Probe.EDECode, Text: r.Probe.EDEText}
	}
	return jr
}

func toJSONSummary(s runner.Summary) jsonSummary {
	counts := map[string]int{}
	for v, n := range s.Counts {
		counts[string(v)] = n
	}
	js := jsonSummary{
		Resolver: s.Resolver,
		Total:    s.Total,
		Counts:   counts,
		Leaks:    s.Leaks,
	}
	if s.BaselineOK {
		ms := s.Baseline.Milliseconds()
		js.BaselineMS = &ms
	}
	return js
}
