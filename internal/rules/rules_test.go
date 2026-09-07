package rules

import (
	"sort"
	"strings"
	"testing"

	"github.com/kubeport/kubeport/internal/catalog"
	"github.com/kubeport/kubeport/internal/loader"
	"github.com/kubeport/kubeport/internal/targets"
)

func run(t *testing.T, fixture, target string) []Finding {
	t.Helper()
	b, err := loader.Load([]string{"../../fixtures/" + fixture}, loader.Options{})
	if err != nil {
		t.Fatal(err)
	}
	to, err := targets.Resolve(target)
	if err != nil {
		t.Fatal(err)
	}
	return Run(&Context{To: to, Bundle: b}, Options{})
}

func ruleSet(fs []Finding) []string {
	seen := map[string]bool{}
	for _, f := range fs {
		seen[f.Rule] = true
	}
	var out []string
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestK3sAppOnOpenShift(t *testing.T) {
	fs := run(t, "k3s-app", "openshift:4.19/vsphere")
	want := []string{
		"img/latest-tag", "k3s/traefik-crd", "net/ingress-on-openshift", "sec/allow-privilege-escalation",
		"sec/capabilities", "sec/fixed-uid", "sec/hostpath", "stor/rwx-unsupported", "stor/storageclass-missing",
	}
	if got := ruleSet(fs); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("rules fired:\n got %v\nwant %v", got, want)
	}
	s := Summarise(fs)
	if s.Errors != 8 || s.Warnings != 3 || s.Infos != 1 || s.Fixable != 8 {
		t.Errorf("summary %+v", s)
	}
}

func TestK3sAppOnK3sIsQuiet(t *testing.T) {
	fs := run(t, "k3s-app", "k3s:1.31")
	// local-path-provisioner only supports ReadWriteOnce, so the RWX claim is a
	// real error even at home; everything else must be informational.
	for _, f := range fs {
		if f.Severity > Info && f.Rule != "stor/rwx-unsupported" {
			t.Errorf("k3s app on k3s: unexpected %s finding %s: %s", f.Sev, f.Rule, f.Message)
		}
	}
}

func TestOcpAppOnK3s(t *testing.T) {
	fs := run(t, "ocp-app", "k3s:1.31")
	want := []string{"img/imagestream-on-non-openshift", "img/latest-tag", "net/route-on-non-openshift", "ocp/deploymentconfig", "ocp/service-ca", "ocp/template-object", "sec/run-as-root"}
	if got := ruleSet(fs); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("rules fired:\n got %v\nwant %v", got, want)
	}
}

func TestOcpAppOnOpenShiftOnlyDeprecation(t *testing.T) {
	fs := run(t, "ocp-app", "openshift:4.19")
	for _, f := range fs {
		if f.Severity == Error {
			t.Errorf("OpenShift app on OpenShift produced an error: %s %s", f.Rule, f.Message)
		}
	}
	found := false
	for _, f := range fs {
		if f.Rule == "api/deprecated" && f.Object == "DeploymentConfig/web" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected api/deprecated for DeploymentConfig, got %v", ruleSet(fs))
	}
}

func TestLegacyAPIs(t *testing.T) {
	fs := run(t, "legacy", "k8s:1.32")
	removed := 0
	for _, f := range fs {
		if f.Rule == "api/removed" {
			removed++
		}
	}
	if removed != 3 {
		t.Errorf("api/removed fired %d times, want 3", removed)
	}
	// On an old enough cluster the CronJob API still exists.
	fs = run(t, "legacy", "k8s:1.29")
	for _, f := range fs {
		if f.Rule == "api/removed" && f.Object == "Ingress/legacy" {
			return
		}
	}
	t.Error("extensions/v1beta1 Ingress must be reported removed on 1.29")
}

func TestCleanIsCleanEverywhere(t *testing.T) {
	for _, target := range []string{"k3s:1.31", "k3s:1.33/hardened", "k8s:1.32", "k8s:1.32/eks", "k8s:1.34/talos", "openshift:4.19", "openshift:4.19/regulated", "openshift:4.20/odf"} {
		fs := run(t, "clean", target)
		if len(fs) != 0 {
			t.Errorf("%s: clean fixture produced findings: %v", target, fs)
		}
	}
}

func TestDisableAndOnly(t *testing.T) {
	b, _ := loader.Load([]string{"../../fixtures/k3s-app"}, loader.Options{})
	to, _ := targets.Resolve("openshift:4.19")
	fs := Run(&Context{To: to, Bundle: b}, Options{Disable: map[string]bool{"sec/fixed-uid": true}})
	for _, f := range fs {
		if f.Rule == "sec/fixed-uid" {
			t.Error("disabled rule still fired")
		}
	}
	fs = Run(&Context{To: to, Bundle: b}, Options{Only: map[string]bool{"sec/hostpath": true}})
	if len(fs) != 1 || fs[0].Rule != "sec/hostpath" {
		t.Errorf("only filter failed: %v", ruleSet(fs))
	}
}

func TestEveryRuleHasCatalogEntry(t *testing.T) {
	for _, id := range IDs() {
		if _, ok := catalog.Rule(id); !ok {
			t.Errorf("rule %s has no entry in catalog/rules.yaml", id)
		}
	}
	for _, m := range catalog.Rules() {
		found := false
		for _, id := range IDs() {
			if id == m.ID {
				found = true
			}
		}
		if !found {
			t.Errorf("catalog rule %s is not implemented", m.ID)
		}
	}
}
