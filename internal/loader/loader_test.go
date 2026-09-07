package loader

import (
	"testing"
)

func TestSplitDocuments(t *testing.T) {
	in := "# head\napiVersion: v1\nkind: A\n---\napiVersion: v1\nkind: B\n--- # trailing comment\nkind: C\n...\n"
	docs := SplitDocuments(in)
	if len(docs) != 3 {
		t.Fatalf("got %d docs: %q", len(docs), docs)
	}
	if docs[0] != "# head\napiVersion: v1\nkind: A\n" || docs[2] != "kind: C\n" {
		t.Errorf("unexpected split: %q", docs)
	}
}

func TestParseDocsSkipsNonObjectsAndExpandsLists(t *testing.T) {
	in := `
# only a comment
---
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: ConfigMap
    metadata: {name: a}
  - apiVersion: v1
    kind: Secret
    metadata: {name: b}
---
just: a map without apiVersion
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: d}
`
	objs, err := parseDocs([]byte(in), "test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 3 {
		t.Fatalf("got %d objects", len(objs))
	}
	if objs[0].Kind() != "ConfigMap" || objs[1].Kind() != "Secret" || objs[2].Kind() != "Deployment" {
		t.Errorf("wrong kinds: %s %s %s", objs[0].Kind(), objs[1].Kind(), objs[2].Kind())
	}
	if objs[2].Raw == "" || objs[0].Raw != "" {
		t.Errorf("Raw should be kept for plain docs and empty for List items")
	}
}

func TestLoadFixtures(t *testing.T) {
	b, err := Load([]string{"../../fixtures/k3s-app"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Objects) != 6 {
		t.Errorf("k3s-app: %d objects, want 6", len(b.Objects))
	}
}
