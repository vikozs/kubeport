// Package catalog holds rule metadata and the API removal table, both embedded
// YAML so contributors can edit them without touching Go.
package catalog

import (
	_ "embed"
	"sort"
	"sync"

	"github.com/goccy/go-yaml"
)

//go:embed rules.yaml
var rulesYAML []byte

//go:embed api-versions.yaml
var apiYAML []byte

// RuleMeta is the human-facing description of a rule.
type RuleMeta struct {
	ID       string `yaml:"id"`
	Title    string `yaml:"title"`
	Summary  string `yaml:"summary"`
	Detail   string `yaml:"detail"`
	Docs     string `yaml:"docs"`
	Fix      string `yaml:"fix"`      // how the autofix works, "" if none
	Category string `yaml:"category"` // sec, net, stor, img, api, ocp, k3s, res
}

// APIVersion is one deprecated or removed API.
type APIVersion struct {
	APIVersion   string `yaml:"apiVersion"`
	Kind         string `yaml:"kind"`
	DeprecatedIn int    `yaml:"deprecated_in"` // Kubernetes minor, e.g. 22
	RemovedIn    int    `yaml:"removed_in"`    // 0 if not yet scheduled
	Replacement  string `yaml:"replacement"`
}

var (
	once  sync.Once
	rules map[string]RuleMeta
	apis  []APIVersion
)

func load() {
	once.Do(func() {
		var rl struct {
			Rules []RuleMeta `yaml:"rules"`
		}
		if err := yaml.Unmarshal(rulesYAML, &rl); err != nil {
			panic("catalog/rules.yaml: " + err.Error())
		}
		rules = map[string]RuleMeta{}
		for _, r := range rl.Rules {
			rules[r.ID] = r
		}
		var al struct {
			APIs []APIVersion `yaml:"apis"`
		}
		if err := yaml.Unmarshal(apiYAML, &al); err != nil {
			panic("catalog/api-versions.yaml: " + err.Error())
		}
		apis = al.APIs
	})
}

// Rule returns metadata for a rule id.
func Rule(id string) (RuleMeta, bool) {
	load()
	r, ok := rules[id]
	return r, ok
}

// Rules returns all rule metadata sorted by id.
func Rules() []RuleMeta {
	load()
	out := make([]RuleMeta, 0, len(rules))
	for _, r := range rules {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// APIs returns the deprecation table.
func APIs() []APIVersion {
	load()
	return apis
}
