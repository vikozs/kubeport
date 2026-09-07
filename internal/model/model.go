// Package model holds the normalised view of Kubernetes objects that rules
// operate on. Objects are kept as generic maps so any kind, including CRDs,
// can be inspected without a typed schema.
package model

import (
	"fmt"
	"strings"
)

// Object is one Kubernetes manifest plus where it came from.
type Object struct {
	Data   map[string]any
	Source string // file path or "stdin" / "helm:<chart>"
	Index  int    // document index within Source
	Raw    string // original document text, "" when synthesised (List items, expanded Templates)
}

// Bundle is the full set of objects under analysis.
type Bundle struct {
	Objects []*Object
}

func (o *Object) APIVersion() string { return str(o.Data["apiVersion"]) }
func (o *Object) Kind() string       { return str(o.Data["kind"]) }

// Group returns the API group ("" for core).
func (o *Object) Group() string {
	av := o.APIVersion()
	if i := strings.Index(av, "/"); i >= 0 {
		return av[:i]
	}
	return ""
}

func (o *Object) Name() string {
	if m, ok := o.Data["metadata"].(map[string]any); ok {
		return str(m["name"])
	}
	return ""
}

func (o *Object) Namespace() string {
	if m, ok := o.Data["metadata"].(map[string]any); ok {
		return str(m["namespace"])
	}
	return ""
}

func (o *Object) Annotations() map[string]any {
	if m, ok := o.Data["metadata"].(map[string]any); ok {
		if a, ok := m["annotations"].(map[string]any); ok {
			return a
		}
	}
	return nil
}

// Ref is the short "Kind/name" identifier used in reports.
func (o *Object) Ref() string {
	n := o.Name()
	if n == "" {
		n = "<unnamed>"
	}
	return o.Kind() + "/" + n
}

// Get walks a dotted path (e.g. "spec.template.spec") and returns the value.
func (o *Object) Get(path string) (any, bool) {
	return Get(o.Data, path)
}

// Get walks a dotted path on an arbitrary map.
func Get(m map[string]any, path string) (any, bool) {
	var cur any = m
	for _, seg := range strings.Split(path, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = mm[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// Set writes a value at a dotted path, creating intermediate maps.
func Set(m map[string]any, path string, v any) {
	segs := strings.Split(path, ".")
	cur := m
	for _, seg := range segs[:len(segs)-1] {
		next, ok := cur[seg].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[seg] = next
		}
		cur = next
	}
	cur[segs[len(segs)-1]] = v
}

// Delete removes a key at a dotted path if present.
func Delete(m map[string]any, path string) {
	segs := strings.Split(path, ".")
	cur := m
	for _, seg := range segs[:len(segs)-1] {
		next, ok := cur[seg].(map[string]any)
		if !ok {
			return
		}
		cur = next
	}
	delete(cur, segs[len(segs)-1])
}

// PodSpec is a pod template found inside a workload, with the JSON-ish path
// prefix where it lives so findings can point at the exact field.
type PodSpec struct {
	Spec map[string]any
	Path string
}

// workloadPodPaths maps kinds to where their pod spec lives.
var workloadPodPaths = map[string]string{
	"Pod":                   "spec",
	"Deployment":            "spec.template.spec",
	"StatefulSet":           "spec.template.spec",
	"DaemonSet":             "spec.template.spec",
	"ReplicaSet":            "spec.template.spec",
	"ReplicationController": "spec.template.spec",
	"Job":                   "spec.template.spec",
	"CronJob":               "spec.jobTemplate.spec.template.spec",
	"DeploymentConfig":      "spec.template.spec",
	"Rollout":               "spec.template.spec",
}

// PodSpecs returns every pod spec embedded in the object (usually 0 or 1).
func (o *Object) PodSpecs() []PodSpec {
	p, ok := workloadPodPaths[o.Kind()]
	if !ok {
		// Knative Service and similar: spec.template.spec with containers.
		if v, ok := o.Get("spec.template.spec.containers"); ok && v != nil {
			p = "spec.template.spec"
		} else {
			return nil
		}
	}
	v, ok := o.Get(p)
	if !ok {
		return nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	return []PodSpec{{Spec: m, Path: p}}
}

// Container is one container within a pod spec.
type Container struct {
	Spec map[string]any
	Path string // e.g. spec.template.spec.containers[0]
	Name string
}

// Containers returns regular, init and ephemeral containers.
func (p PodSpec) Containers() []Container {
	var out []Container
	for _, key := range []string{"containers", "initContainers", "ephemeralContainers"} {
		list, ok := p.Spec[key].([]any)
		if !ok {
			continue
		}
		for i, c := range list {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			out = append(out, Container{
				Spec: cm,
				Path: fmt.Sprintf("%s.%s[%d]", p.Path, key, i),
				Name: str(cm["name"]),
			})
		}
	}
	return out
}

// SecurityContext returns the pod-level security context (may be nil).
func (p PodSpec) SecurityContext() map[string]any {
	sc, _ := p.Spec["securityContext"].(map[string]any)
	return sc
}

// SecurityContext returns the container-level security context (may be nil).
func (c Container) SecurityContext() map[string]any {
	sc, _ := c.Spec["securityContext"].(map[string]any)
	return sc
}

// Volumes returns the pod volumes list.
func (p PodSpec) Volumes() []map[string]any {
	list, _ := p.Spec["volumes"].([]any)
	var out []map[string]any
	for _, v := range list {
		if m, ok := v.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func str(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

// Str is the exported string coercion helper.
func Str(v any) string { return str(v) }

// Bool coerces a YAML value to bool.
func Bool(v any) (bool, bool) {
	b, ok := v.(bool)
	return b, ok
}

// Int64 coerces a YAML number to int64.
func Int64(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case uint64:
		return int64(n), true
	case float64:
		return int64(n), true
	}
	return 0, false
}
