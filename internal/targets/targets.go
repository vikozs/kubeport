// Package targets describes what a destination cluster accepts. Facts live in
// YAML files (embedded from /targets) so they can be updated without code.
package targets

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml"
)

//go:embed all:data
var data embed.FS

// Target is one distribution+version, optionally refined by a profile.
type Target struct {
	Name       string `yaml:"name"`       // k3s | k8s | openshift
	Version    string `yaml:"version"`    // distribution version, e.g. 4.19 or 1.32
	Kubernetes string `yaml:"kubernetes"` // bundled Kubernetes minor, e.g. 1.32
	Display    string `yaml:"display"`
	Profile    string `yaml:"profile"` // e.g. eks, hosted; "" for default
	Notes      string `yaml:"notes"`

	// Admission model: "scc" (OpenShift), "psa" (Pod Security Admission) or "none".
	Admission string `yaml:"admission"`
	// PSALevel is the enforced PSA level when Admission == psa: privileged|baseline|restricted.
	PSALevel string `yaml:"psa_level"`
	// DefaultSCC is the SCC an unprivileged service account gets on OpenShift.
	DefaultSCC        string `yaml:"default_scc"`
	ArbitraryUID      bool   `yaml:"arbitrary_uid"`
	HostPathAllowed   bool   `yaml:"hostpath_allowed"`
	PrivilegedAllowed bool   `yaml:"privileged_allowed"`

	Ingress struct {
		DefaultClass       string   `yaml:"default_class"`
		Controller         string   `yaml:"controller"`
		Routes             bool     `yaml:"routes"`
		AnnotationPrefixes []string `yaml:"annotation_prefixes"`
	} `yaml:"ingress"`

	LoadBalancer bool `yaml:"load_balancer"` // Service type=LoadBalancer gets an external address

	Storage struct {
		Classes      []string `yaml:"classes"`
		DefaultClass string   `yaml:"default_class"`
		RWXClasses   []string `yaml:"rwx_classes"`
		// Mapping suggests replacements for foreign classes when translating.
		Mapping map[string]string `yaml:"mapping"`
	} `yaml:"storage"`

	// APIGroups lists the CRD/aggregated API groups known to exist on the target.
	APIGroups []string `yaml:"api_groups"`

	// Quotas: when true, treat missing requests/limits as errors.
	QuotasEnforced bool `yaml:"quotas_enforced"`
	// NetworkPolicyDefaultDeny: workloads without a NetworkPolicy will be isolated.
	NetworkPolicyDefaultDeny bool `yaml:"network_policy_default_deny"`
}

// ID returns the canonical "name:version[/profile]" string.
func (t *Target) ID() string {
	id := t.Name + ":" + t.Version
	if t.Profile != "" {
		id += "/" + t.Profile
	}
	return id
}

// KubeMinor returns the bundled Kubernetes minor as an integer (e.g. 32).
func (t *Target) KubeMinor() int {
	parts := strings.Split(t.Kubernetes, ".")
	if len(parts) < 2 {
		return 0
	}
	n, _ := strconv.Atoi(parts[1])
	return n
}

func (t *Target) HasAPIGroup(group string) bool {
	for _, g := range t.APIGroups {
		if g == group {
			return true
		}
	}
	return false
}

func (t *Target) HasStorageClass(name string) bool {
	for _, c := range t.Storage.Classes {
		if c == name {
			return true
		}
	}
	return false
}

func (t *Target) SupportsRWX(class string) bool {
	if class == "" {
		class = t.Storage.DefaultClass
	}
	for _, c := range t.Storage.RWXClasses {
		if c == class {
			return true
		}
	}
	return false
}

// IsOpenShift is sugar used by rules.
func (t *Target) IsOpenShift() bool { return t.Name == "openshift" }
func (t *Target) IsK3s() bool       { return t.Name == "k3s" }

// Resolve parses "openshift:4.19", "k8s:1.32/eks", "k3s" (latest) or a path to
// a profile YAML and returns a fully populated target.
func Resolve(spec string) (*Target, error) {
	if strings.HasSuffix(spec, ".yaml") || strings.HasSuffix(spec, ".yml") {
		return loadProfileFile(spec)
	}
	name, version, profile := split(spec)
	if version == "" {
		v, err := latestVersion(name)
		if err != nil {
			return nil, err
		}
		version = v
	}
	base, err := loadEmbedded(fmt.Sprintf("data/%s/%s.yaml", name, version))
	if err != nil {
		return nil, fmt.Errorf("unknown target %q (run `kubeport targets`)", spec)
	}
	if profile != "" {
		short := base.Display
		if err := overlayEmbedded(base, fmt.Sprintf("data/%s/profiles/%s.yaml", name, profile)); err != nil {
			return nil, fmt.Errorf("profile %q for %s:%s: %w", profile, name, version, err)
		}
		base.Profile = profile
		base.Display = short + " (" + base.Display + ")"
	}
	return base, nil
}

// ResolveAll parses a comma-separated list of target specs.
func ResolveAll(specs string) ([]*Target, error) {
	var out []*Target
	for _, s := range strings.Split(specs, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		t, err := Resolve(s)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no target given (use --to)")
	}
	return out, nil
}

func split(spec string) (name, version, profile string) {
	if i := strings.Index(spec, "/"); i >= 0 {
		profile = spec[i+1:]
		spec = spec[:i]
	}
	name = spec
	if i := strings.Index(spec, ":"); i >= 0 {
		name = spec[:i]
		version = spec[i+1:]
	}
	switch name {
	case "kubernetes", "vanilla", "upstream":
		name = "k8s"
	case "ocp", "okd":
		name = "openshift"
	}
	return
}

func loadEmbedded(path string) (*Target, error) {
	b, err := data.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t Target
	if err := yaml.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &t, nil
}

// overlayEmbedded merges a profile file on top of a base target. Lists and
// scalars in the profile replace the base; maps (storage mapping) are merged.
func overlayEmbedded(base *Target, path string) error {
	b, err := data.ReadFile(path)
	if err != nil {
		return err
	}
	return overlayBytes(base, b)
}

func overlayBytes(base *Target, b []byte) error {
	// Marshal the base back to a generic map, unmarshal the overlay into a
	// generic map, merge, and decode into the struct. Keeps this free of
	// reflection over the Target fields.
	var bm, om map[string]any
	baseBytes, _ := yaml.Marshal(base)
	if err := yaml.Unmarshal(baseBytes, &bm); err != nil {
		return err
	}
	if err := yaml.Unmarshal(b, &om); err != nil {
		return err
	}
	merged := merge(bm, om)
	out, _ := yaml.Marshal(merged)
	return yaml.Unmarshal(out, base)
}

func merge(dst, src map[string]any) map[string]any {
	for k, v := range src {
		if sm, ok := v.(map[string]any); ok {
			if dm, ok := dst[k].(map[string]any); ok {
				dst[k] = merge(dm, sm)
				continue
			}
		}
		dst[k] = v
	}
	return dst
}

// loadProfileFile reads a user profile. It must declare `extends: k8s:1.32`
// (or similar); every other field overlays the base.
func loadProfileFile(path string) (*Target, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var head struct {
		Extends string `yaml:"extends"`
	}
	if err := yaml.Unmarshal(b, &head); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if head.Extends == "" {
		return nil, fmt.Errorf("%s: profile must set `extends: <name>:<version>`", path)
	}
	base, err := Resolve(head.Extends)
	if err != nil {
		return nil, err
	}
	short := base.Display
	if err := overlayBytes(base, b); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if base.Display != short {
		base.Display = short + " (" + base.Display + ")"
	}
	if base.Profile == "" {
		base.Profile = strings.TrimSuffix(strings.TrimSuffix(fileBase(path), ".yaml"), ".yml")
	}
	return base, nil
}

func fileBase(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// Entry describes one shipped target or profile for `kubeport targets`.
type Entry struct {
	ID         string
	Display    string
	Kubernetes string
	Profiles   []string
}

// List enumerates every embedded target.
func List() ([]Entry, error) {
	var out []Entry
	names, err := fs.ReadDir(data, "data")
	if err != nil {
		return nil, err
	}
	for _, d := range names {
		if !d.IsDir() {
			continue
		}
		files, _ := fs.ReadDir(data, "data/"+d.Name())
		var profiles []string
		if pf, err := fs.ReadDir(data, "data/"+d.Name()+"/profiles"); err == nil {
			for _, p := range pf {
				profiles = append(profiles, strings.TrimSuffix(p.Name(), ".yaml"))
			}
		}
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".yaml") {
				continue
			}
			t, err := loadEmbedded("data/" + d.Name() + "/" + f.Name())
			if err != nil {
				return nil, err
			}
			out = append(out, Entry{ID: t.ID(), Display: t.Display, Kubernetes: t.Kubernetes, Profiles: profiles})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func latestVersion(name string) (string, error) {
	files, err := fs.ReadDir(data, "data/"+name)
	if err != nil {
		return "", fmt.Errorf("unknown distribution %q (k3s, k8s, openshift)", name)
	}
	var versions []string
	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".yaml") {
			versions = append(versions, strings.TrimSuffix(f.Name(), ".yaml"))
		}
	}
	if len(versions) == 0 {
		return "", fmt.Errorf("no versions for %s", name)
	}
	sort.Slice(versions, func(i, j int) bool { return versionLess(versions[j], versions[i]) })
	return versions[0], nil
}

func versionLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x < y
		}
	}
	return len(pa) < len(pb)
}

// ProfileTemplate returns a starter profile file for `kubeport profile init`.
func ProfileTemplate(extends string) string {
	return fmt.Sprintf(`# kubeport cluster profile
# Describe what YOUR cluster accepts. Anything omitted inherits from `+"`extends`"+`.
extends: %s
profile: my-cluster
display: My production cluster

# Admission: for OpenShift keep scc; for k8s/k3s choose psa + level.
# admission: psa
# psa_level: restricted

storage:
  classes: [thin-csi, ocs-storagecluster-ceph-rbd, ocs-storagecluster-cephfs]
  default_class: thin-csi
  rwx_classes: [ocs-storagecluster-cephfs]
  mapping:
    local-path: thin-csi
    gp2: thin-csi
    gp3: thin-csi
    standard: thin-csi

ingress:
  default_class: openshift-default

# CRD API groups installed on the cluster (kubectl api-resources -o name | awk -F. 'NF>1{sub($1".","");print}' | sort -u)
api_groups:
  - monitoring.coreos.com
  - cert-manager.io
  - external-secrets.io

quotas_enforced: true
network_policy_default_deny: true
`, extends)
}
