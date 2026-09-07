package translate

import (
	"strings"
	"testing"

	"github.com/kubeport/kubeport/internal/loader"
	"github.com/kubeport/kubeport/internal/model"
	"github.com/kubeport/kubeport/internal/rules"
	"github.com/kubeport/kubeport/internal/targets"
)

func translateFixture(t *testing.T, fixture, target string) (*model.Bundle, *Result, []rules.Finding, *targets.Target) {
	t.Helper()
	b, err := loader.Load([]string{"../../fixtures/" + fixture}, loader.Options{})
	if err != nil {
		t.Fatal(err)
	}
	to, err := targets.Resolve(target)
	if err != nil {
		t.Fatal(err)
	}
	fs := rules.Run(&rules.Context{To: to, Bundle: b}, rules.Options{})
	res := Apply(b, to, fs, nil)
	after := rules.Run(&rules.Context{To: to, Bundle: b}, rules.Options{})
	return b, res, after, to
}

func TestK3sToOpenShiftRemovesAllFixable(t *testing.T) {
	_, res, after, _ := translateFixture(t, "k3s-app", "openshift:4.19/vsphere")
	if len(res.Changes) != 6 {
		t.Errorf("expected 6 changes, got %d: %+v", len(res.Changes), res.Changes)
	}
	for _, f := range after {
		if f.Fixable {
			t.Errorf("fixable finding left after translation: %s %s", f.Rule, f.Message)
		}
	}
	s := rules.Summarise(after)
	if s.Errors != 3 { // traefik CRD, hostPath, RWX: need a human
		t.Errorf("expected 3 residual errors, got %+v", s)
	}
}

func TestOcpToK3sConversions(t *testing.T) {
	b, res, _, _ := translateFixture(t, "ocp-app", "k3s:1.31")
	kinds := map[string]int{}
	for _, o := range b.Objects {
		kinds[o.Kind()]++
	}
	if kinds["Route"] != 0 || kinds["Ingress"] != 1 || kinds["DeploymentConfig"] != 0 || kinds["Deployment"] != 2 || kinds["Template"] != 0 {
		t.Errorf("unexpected kinds after translation: %v", kinds)
	}
	for _, o := range b.Objects {
		if o.Kind() == "Deployment" && o.Name() == "cache" {
			if v, _ := o.Get("spec.replicas"); v != int64(2) {
				t.Errorf("${{REPLICAS}} should become int 2, got %#v", v)
			}
			if v, _ := o.Get("spec.template.spec.containers"); !strings.Contains(mustMarshal(o), "${PASSWORD}") {
				t.Errorf("generated parameter should stay a placeholder: %v", v)
			}
		}
		if o.Kind() == "Ingress" {
			if v, _ := o.Get("spec.ingressClassName"); v != "traefik" {
				t.Errorf("Ingress should get k3s default class, got %v", v)
			}
			if v, _ := o.Get("spec.rules"); v == nil {
				t.Error("Ingress has no rules")
			}
		}
		if o.Kind() == "Deployment" && o.Name() == "web" {
			if v, _ := o.Get("spec.strategy.type"); v != "RollingUpdate" {
				t.Errorf("strategy not mapped: %v", v)
			}
			if _, ok := o.Get("spec.triggers"); ok {
				t.Error("triggers should be dropped")
			}
		}
	}
	if len(res.Notes) == 0 {
		t.Error("expected manual notes for ImageChange trigger and TLS")
	}
}

func TestLegacyIngressBackendConversion(t *testing.T) {
	b, _, after, _ := translateFixture(t, "legacy", "k8s:1.32/eks")
	for _, o := range b.Objects {
		if o.Kind() == "Ingress" {
			if o.APIVersion() != "networking.k8s.io/v1" {
				t.Errorf("apiVersion not rewritten: %s", o.APIVersion())
			}
			if v, _ := o.Get("spec.rules"); !strings.Contains(mustMarshal(o), "number: 80") || v == nil {
				t.Errorf("backend not converted: %s", mustMarshal(o))
			}
			if v, _ := o.Get("spec.ingressClassName"); v != "alb" {
				t.Errorf("class should follow EKS default, got %v", v)
			}
		}
		if o.Kind() == "CronJob" && o.APIVersion() != "batch/v1" {
			t.Errorf("CronJob apiVersion %s", o.APIVersion())
		}
	}
	for _, f := range after {
		if f.Rule == "api/removed" && f.Object != "PodSecurityPolicy/restricted" {
			t.Errorf("api/removed still fires for %s", f.Object)
		}
	}
}

func TestRenderKeepsUnchangedVerbatimAndHeaderComments(t *testing.T) {
	b, res, _, _ := translateFixture(t, "k3s-app", "openshift:4.19/vsphere")
	files, err := RenderAll(b.Objects, res.Modified, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f.Source, "deployment.yaml") && !strings.HasPrefix(f.After, "# A typical app that grew up on k3s.\n") {
			t.Errorf("header comment lost:\n%s", f.After)
		}
		if strings.HasSuffix(f.Source, "service.yaml") {
			// Service was untouched: its original text must survive byte for byte.
			if !strings.Contains(f.After, "  type: LoadBalancer\n  selector:\n    app: api\n") {
				t.Errorf("unchanged Service was re-serialised:\n%s", f.After)
			}
			if !strings.Contains(f.After, "kind: Route") || strings.Contains(f.After, "kind: Ingress") {
				t.Errorf("Ingress should be replaced by Route:\n%s", f.After)
			}
		}
	}
}

func TestUnifiedDiff(t *testing.T) {
	a := "a\nb\nc\nd\ne\nf\ng\nh\n"
	b := "a\nb\nc\nX\ne\nf\ng\nh\n"
	d := UnifiedDiff("/x.yaml", a, b)
	if !strings.Contains(d, "--- a/x.yaml") || !strings.Contains(d, "@@ -1,7 +1,7 @@") || !strings.Contains(d, "-d\n+X\n") {
		t.Errorf("unexpected diff:\n%s", d)
	}
	if UnifiedDiff("s", "same\n", "same\n") != "--- a/s\n+++ b/s\n" {
		t.Error("identical inputs should produce a header only")
	}
}

func mustMarshal(o *model.Object) string {
	b, _ := Marshal(o)
	return string(b)
}
