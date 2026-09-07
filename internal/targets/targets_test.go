package targets

import "testing"

func TestResolve(t *testing.T) {
	cases := map[string]struct {
		id, display string
		minor       int
	}{
		"openshift:4.19":         {"openshift:4.19", "OpenShift 4.19", 32},
		"ocp:4.18":               {"openshift:4.18", "OpenShift 4.18", 31},
		"k8s:1.32/eks":           {"k8s:1.32/eks", "Kubernetes 1.32 (Amazon EKS)", 32},
		"kubernetes:1.30":        {"k8s:1.30", "Kubernetes 1.30", 30},
		"k3s:1.31":               {"k3s:1.31", "k3s 1.31", 31},
		"openshift:4.19/vsphere": {"openshift:4.19/vsphere", "OpenShift 4.19 (vSphere, thin-csi)", 32},
	}
	for spec, want := range cases {
		got, err := Resolve(spec)
		if err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		if got.ID() != want.id || got.Display != want.display || got.KubeMinor() != want.minor {
			t.Errorf("%s: got %s / %q / %d, want %s / %q / %d", spec, got.ID(), got.Display, got.KubeMinor(), want.id, want.display, want.minor)
		}
	}
}

func TestLatestVersion(t *testing.T) {
	got, err := Resolve("openshift")
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != "4.20" {
		t.Errorf("latest openshift = %s, want 4.20", got.Version)
	}
}

func TestProfileOverlayKeepsBase(t *testing.T) {
	got, err := Resolve("openshift:4.19/odf")
	if err != nil {
		t.Fatal(err)
	}
	if got.Admission != "scc" || got.DefaultSCC != "restricted-v2" {
		t.Errorf("profile overlay lost base admission facts: %+v", got)
	}
	if !got.SupportsRWX("ocs-storagecluster-cephfs") || got.SupportsRWX("ocs-storagecluster-ceph-rbd") {
		t.Errorf("RWX classes wrong: %v", got.Storage.RWXClasses)
	}
	if !got.HasAPIGroup("route.openshift.io") {
		t.Errorf("api groups lost in overlay")
	}
}

func TestEveryShippedTargetLoads(t *testing.T) {
	list, err := List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) < 15 {
		t.Fatalf("only %d targets", len(list))
	}
	for _, e := range list {
		if _, err := Resolve(e.ID); err != nil {
			t.Errorf("%s: %v", e.ID, err)
		}
		for _, p := range e.Profiles {
			if _, err := Resolve(e.ID + "/" + p); err != nil {
				t.Errorf("%s/%s: %v", e.ID, p, err)
			}
		}
	}
}

func TestUnknown(t *testing.T) {
	if _, err := Resolve("rancher:2.9"); err == nil {
		t.Error("expected error for unknown distribution")
	}
	if _, err := Resolve("k3s:9.9"); err == nil {
		t.Error("expected error for unknown version")
	}
}
