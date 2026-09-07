// Package report renders findings as text, JSON, SARIF or a Markdown matrix.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/kubeport/kubeport/internal/catalog"
	"github.com/kubeport/kubeport/internal/rules"
	"github.com/kubeport/kubeport/internal/targets"
)

// TargetResult is the outcome for one target.
type TargetResult struct {
	Target   *targets.Target `json:"-"`
	TargetID string          `json:"target"`
	Display  string          `json:"display"`
	Findings []rules.Finding `json:"findings"`
	Summary  rules.Summary   `json:"summary"`
}

// Run is a whole check run.
type Run struct {
	Version string         `json:"kubeport"`
	From    string         `json:"from,omitempty"`
	Inputs  []string       `json:"inputs"`
	Objects int            `json:"objects"`
	Results []TargetResult `json:"results"`
}

// Colors are enabled when writing to a terminal and NO_COLOR is unset.
var Color = func() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}()

func paint(code, s string) string {
	if !Color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func sevLabel(s rules.Severity) string {
	switch s {
	case rules.Error:
		return paint("31;1", "ERROR")
	case rules.Warn:
		return paint("33;1", "WARN ")
	default:
		return paint("36", "INFO ")
	}
}

// Text writes the human report.
func Text(w io.Writer, r Run) {
	for i, tr := range r.Results {
		if i > 0 {
			fmt.Fprintln(w)
		}
		head := fmt.Sprintf("kubeport %s · %d objects", r.Version, r.Objects)
		if r.From != "" {
			head += " · " + r.From + " -> " + tr.TargetID
		} else {
			head += " · -> " + tr.TargetID
		}
		fmt.Fprintln(w, paint("1", head))
		if len(tr.Findings) == 0 {
			fmt.Fprintln(w, paint("32", "  no portability findings"))
			continue
		}
		for _, f := range tr.Findings {
			loc := f.Object
			if f.Path != "" {
				loc += "  " + paint("2", f.Path)
			}
			fmt.Fprintf(w, "%s  %-32s %s\n", sevLabel(f.Severity), f.Rule, loc)
			for _, line := range wrap(f.Message, 96) {
				fmt.Fprintf(w, "       %s\n", line)
			}
			if f.Fixable {
				fmt.Fprintf(w, "       %s\n", paint("32", "fix available: kubeport translate --to "+tr.TargetID+" --rule "+f.Rule))
			}
		}
		s := tr.Summary
		fmt.Fprintf(w, "\n%d finding(s) (%d error, %d warn, %d info) · %d autofixable · kubeport explain <rule> for details\n",
			len(tr.Findings), s.Errors, s.Warnings, s.Infos, s.Fixable)
	}
}

func wrap(s string, width int) []string {
	var lines []string
	words := strings.Fields(s)
	cur := ""
	for _, wd := range words {
		if cur != "" && len(cur)+1+len(wd) > width {
			lines = append(lines, cur)
			cur = wd
			continue
		}
		if cur == "" {
			cur = wd
		} else {
			cur += " " + wd
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// JSON writes the machine report.
func JSON(w io.Writer, r Run) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// SARIF writes a SARIF 2.1.0 log for GitHub code scanning and similar.
func SARIF(w io.Writer, r Run) error {
	type msg struct {
		Text string `json:"text"`
	}
	type ruleDesc struct {
		ID               string            `json:"id"`
		Name             string            `json:"name"`
		ShortDescription msg               `json:"shortDescription"`
		FullDescription  msg               `json:"fullDescription"`
		HelpURI          string            `json:"helpUri,omitempty"`
		Properties       map[string]string `json:"properties,omitempty"`
	}
	type region struct {
		StartLine int `json:"startLine"`
	}
	type artifact struct {
		URI string `json:"uri"`
	}
	type physical struct {
		ArtifactLocation artifact `json:"artifactLocation"`
		Region           region   `json:"region"`
	}
	type location struct {
		PhysicalLocation physical `json:"physicalLocation"`
		LogicalLocations []struct {
			Name string `json:"name"`
		} `json:"logicalLocations,omitempty"`
	}
	type result struct {
		RuleID    string            `json:"ruleId"`
		Level     string            `json:"level"`
		Message   msg               `json:"message"`
		Locations []location        `json:"locations"`
		Props     map[string]string `json:"properties,omitempty"`
	}
	type driver struct {
		Name           string     `json:"name"`
		Version        string     `json:"version"`
		InformationURI string     `json:"informationUri"`
		Rules          []ruleDesc `json:"rules"`
	}
	type tool struct {
		Driver driver `json:"driver"`
	}
	type run struct {
		Tool    tool     `json:"tool"`
		Results []result `json:"results"`
	}
	type log struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []run  `json:"runs"`
	}

	var rd []ruleDesc
	seen := map[string]bool{}
	var results []result
	for _, tr := range r.Results {
		for _, f := range tr.Findings {
			if !seen[f.Rule] {
				seen[f.Rule] = true
				meta, _ := catalog.Rule(f.Rule)
				rd = append(rd, ruleDesc{ID: f.Rule, Name: meta.Title, ShortDescription: msg{meta.Summary}, FullDescription: msg{strings.TrimSpace(meta.Detail)}, HelpURI: meta.Docs,
					Properties: map[string]string{"category": meta.Category}})
			}
			level := "note"
			switch f.Severity {
			case rules.Error:
				level = "error"
			case rules.Warn:
				level = "warning"
			}
			uri := f.Source
			if uri == "" {
				uri = "bundle"
			}
			loc := location{PhysicalLocation: physical{ArtifactLocation: artifact{URI: uri}, Region: region{StartLine: 1}}}
			loc.LogicalLocations = []struct {
				Name string `json:"name"`
			}{{Name: f.Object}}
			results = append(results, result{RuleID: f.Rule, Level: level, Message: msg{fmt.Sprintf("[%s] %s: %s", tr.TargetID, f.Object, f.Message)}, Locations: []location{loc},
				Props: map[string]string{"target": tr.TargetID, "path": f.Path, "fixable": fmt.Sprint(f.Fixable)}})
		}
	}
	sort.Slice(rd, func(i, j int) bool { return rd[i].ID < rd[j].ID })
	out := log{Schema: "https://json.schemastore.org/sarif-2.1.0.json", Version: "2.1.0", Runs: []run{{
		Tool:    tool{Driver: driver{Name: "kubeport", Version: r.Version, InformationURI: "https://kubeport.kosir.info", Rules: rd}},
		Results: results,
	}}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// Matrix writes a Markdown compatibility matrix suitable for a README.
func Matrix(w io.Writer, r Run) {
	fmt.Fprintln(w, "| Target | Result | Errors | Warnings | Autofixable |")
	fmt.Fprintln(w, "|---|---|---|---|---|")
	for _, tr := range r.Results {
		status := "✅ compatible"
		if tr.Summary.Errors > 0 {
			status = "❌ blocked"
		} else if tr.Summary.Warnings > 0 {
			status = "⚠️ review"
		}
		fmt.Fprintf(w, "| %s | %s | %d | %d | %d |\n", tr.Display, status, tr.Summary.Errors, tr.Summary.Warnings, tr.Summary.Fixable)
	}
	fmt.Fprintf(w, "\n<sub>Checked with [kubeport](https://kubeport.kosir.info) %s</sub>\n", r.Version)
}

// Badge writes a shields.io endpoint JSON for the overall result.
func Badge(w io.Writer, r Run) error {
	worst := "compatible"
	color := "brightgreen"
	var parts []string
	for _, tr := range r.Results {
		mark := "✓"
		if tr.Summary.Errors > 0 {
			mark = "✗"
			worst = "blocked"
			color = "red"
		} else if tr.Summary.Warnings > 0 && worst != "blocked" {
			worst = "review"
			color = "yellow"
		}
		parts = append(parts, tr.Target.Name+" "+mark)
	}
	return json.NewEncoder(w).Encode(map[string]any{
		"schemaVersion": 1,
		"label":         "kubeport",
		"message":       strings.Join(parts, " · ") + " · " + worst,
		"color":         color,
	})
}
