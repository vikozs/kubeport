// Package rules implements the portability checks. Each rule inspects one
// object (or the whole bundle) against a target and returns findings.
package rules

import (
	"sort"
	"strings"

	"github.com/kubeport/kubeport/internal/catalog"
	"github.com/kubeport/kubeport/internal/model"
	"github.com/kubeport/kubeport/internal/targets"
)

// Severity of a finding. Higher is worse.
type Severity int

const (
	Info Severity = iota
	Warn
	Error
)

func (s Severity) String() string {
	switch s {
	case Error:
		return "error"
	case Warn:
		return "warn"
	default:
		return "info"
	}
}

// ParseSeverity turns "error"/"warn"/"info" into a Severity.
func ParseSeverity(s string) (Severity, bool) {
	switch strings.ToLower(s) {
	case "error", "err":
		return Error, true
	case "warn", "warning":
		return Warn, true
	case "info", "none":
		return Info, true
	}
	return Info, false
}

// Finding is one portability problem.
type Finding struct {
	Rule     string   `json:"rule"`
	Severity Severity `json:"-"`
	Sev      string   `json:"severity"`
	Object   string   `json:"object"`
	Source   string   `json:"source,omitempty"`
	Path     string   `json:"path,omitempty"`
	Message  string   `json:"message"`
	Fixable  bool     `json:"fixable"`
	Target   string   `json:"target"`
	Docs     string   `json:"docs,omitempty"`
	obj      *model.Object
}

// Obj returns the object the finding refers to (nil for bundle-level).
func (f Finding) Obj() *model.Object { return f.obj }

// Context is what rules see.
type Context struct {
	From   *targets.Target // may be nil
	To     *targets.Target
	Bundle *model.Bundle
}

// Strict reports whether the target enforces restricted pod security
// (OpenShift restricted-v2 or PSA restricted).
func (c *Context) Strict() bool {
	return c.To.Admission == "scc" || (c.To.Admission == "psa" && c.To.PSALevel == "restricted")
}

// Baseline reports whether at least PSA baseline (or SCC) applies.
func (c *Context) Baseline() bool {
	return c.Strict() || (c.To.Admission == "psa" && c.To.PSALevel == "baseline")
}

func (c *Context) finding(rule string, sev Severity, obj *model.Object, path, msg string, fixable bool) Finding {
	f := Finding{Rule: rule, Severity: sev, Sev: sev.String(), Path: path, Message: msg, Fixable: fixable, Target: c.To.ID(), obj: obj}
	if obj != nil {
		f.Object = obj.Ref()
		f.Source = obj.Source
	} else {
		f.Object = "(bundle)"
	}
	if meta, ok := catalog.Rule(rule); ok {
		f.Docs = meta.Docs
	}
	return f
}

// Rule checks one object.
type Rule interface {
	ID() string
	Check(c *Context, obj *model.Object) []Finding
}

// BundleRule checks the whole bundle at once.
type BundleRule interface {
	ID() string
	CheckBundle(c *Context) []Finding
}

var registry []any

func register(r any) { registry = append(registry, r) }

// marker registers an id that is emitted by another rule's Check, so it shows
// up in `kubeport rules` and can be disabled.
type marker string

func (m marker) ID() string                            { return string(m) }
func (marker) Check(*Context, *model.Object) []Finding { return nil }

func init() {
	register(marker("api/deprecated"))
	register(marker("net/foreign-ingress-annotations"))
}

// IDs lists registered rule ids.
func IDs() []string {
	var out []string
	for _, r := range registry {
		switch rr := r.(type) {
		case Rule:
			out = append(out, rr.ID())
		case BundleRule:
			out = append(out, rr.ID())
		}
	}
	sort.Strings(out)
	return out
}

// Options control a run.
type Options struct {
	Disable map[string]bool // rule ids to skip
	Only    map[string]bool // if non-empty, run only these
}

func (o Options) enabled(id string) bool {
	if o.Disable[id] {
		return false
	}
	if len(o.Only) > 0 && !o.Only[id] {
		return false
	}
	return true
}

// Run evaluates every rule against every object for one target.
func Run(c *Context, opt Options) []Finding {
	var out []Finding
	for _, r := range registry {
		switch rr := r.(type) {
		case Rule:
			if !opt.enabled(rr.ID()) {
				continue
			}
			for _, obj := range c.Bundle.Objects {
				out = append(out, rr.Check(c, obj)...)
			}
		case BundleRule:
			if !opt.enabled(rr.ID()) {
				continue
			}
			out = append(out, rr.CheckBundle(c)...)
		}
	}
	// Some rules emit findings under a sibling id (api/removed also emits
	// api/deprecated); apply enable/disable on the finding's own id.
	filtered := out[:0]
	for _, f := range out {
		if opt.enabled(f.Rule) {
			filtered = append(filtered, f)
		}
	}
	out = filtered
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		if out[i].Rule != out[j].Rule {
			return out[i].Rule < out[j].Rule
		}
		return out[i].Object < out[j].Object
	})
	return out
}

// Summary counts findings per severity.
type Summary struct {
	Errors, Warnings, Infos, Fixable int
}

func Summarise(fs []Finding) Summary {
	var s Summary
	for _, f := range fs {
		switch f.Severity {
		case Error:
			s.Errors++
		case Warn:
			s.Warnings++
		default:
			s.Infos++
		}
		if f.Fixable {
			s.Fixable++
		}
	}
	return s
}

// Max returns the highest severity present (Info when empty).
func Max(fs []Finding) Severity {
	m := Info
	for _, f := range fs {
		if f.Severity > m {
			m = f.Severity
		}
	}
	return m
}

// builtinGroups are API groups every conformant Kubernetes has.
var builtinGroups = map[string]bool{
	"": true, "apps": true, "batch": true, "autoscaling": true, "policy": true,
	"networking.k8s.io": true, "rbac.authorization.k8s.io": true, "storage.k8s.io": true,
	"apiextensions.k8s.io": true, "admissionregistration.k8s.io": true,
	"certificates.k8s.io": true, "coordination.k8s.io": true, "discovery.k8s.io": true,
	"events.k8s.io": true, "node.k8s.io": true, "scheduling.k8s.io": true,
	"flowcontrol.apiserver.k8s.io": true, "authentication.k8s.io": true,
	"authorization.k8s.io": true, "apiregistration.k8s.io": true, "extensions": true,
	"resource.k8s.io": true, "kustomize.config.k8s.io": true,
}

// IsBuiltinGroup reports whether the group ships with every Kubernetes.
func IsBuiltinGroup(g string) bool { return builtinGroups[g] }
