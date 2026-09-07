// Package loader turns paths into a model.Bundle. It understands plain YAML
// files and directories, Helm charts (rendered with `helm template`) and
// Kustomize overlays (rendered with `kubectl kustomize` or `kustomize build`).
package loader

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/kubeport/kubeport/internal/model"
)

// Options tune how inputs are rendered.
type Options struct {
	HelmValues  []string // -f files passed to helm template
	HelmRelease string   // release name for helm template (default "kubeport")
	NoRender    bool     // treat charts/kustomizations as plain YAML dirs
}

// Load reads every path and returns one bundle.
func Load(paths []string, opt Options) (*model.Bundle, error) {
	b := &model.Bundle{}
	for _, p := range paths {
		if p == "-" {
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				return nil, err
			}
			objs, err := parseDocs(data, "stdin")
			if err != nil {
				return nil, err
			}
			b.Objects = append(b.Objects, objs...)
			continue
		}
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			objs, err := loadDir(p, opt)
			if err != nil {
				return nil, err
			}
			b.Objects = append(b.Objects, objs...)
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		objs, err := parseDocs(data, p)
		if err != nil {
			return nil, err
		}
		b.Objects = append(b.Objects, objs...)
	}
	return b, nil
}

func loadDir(dir string, opt Options) ([]*model.Object, error) {
	if !opt.NoRender {
		if exists(filepath.Join(dir, "Chart.yaml")) {
			if _, err := exec.LookPath("helm"); err == nil {
				return renderHelm(dir, opt)
			}
			fmt.Fprintf(os.Stderr, "kubeport: %s looks like a Helm chart but `helm` is not on PATH; scanning templates as plain YAML\n", dir)
		}
		if exists(filepath.Join(dir, "kustomization.yaml")) || exists(filepath.Join(dir, "kustomization.yml")) {
			if out, err := renderKustomize(dir); err == nil {
				return parseDocs(out, "kustomize:"+dir)
			} else {
				fmt.Fprintf(os.Stderr, "kubeport: could not render kustomization in %s (%v); scanning as plain YAML\n", dir, err)
			}
		}
	}
	var files []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			base := d.Name()
			if base != "." && (strings.HasPrefix(base, ".") || base == "node_modules" || base == "charts") {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" || ext == ".json" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var out []*model.Object
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		objs, err := parseDocs(data, f)
		if err != nil {
			// Helm templates with untemplated {{ }} are not valid YAML; skip with a note.
			fmt.Fprintf(os.Stderr, "kubeport: skipping %s: %v\n", f, err)
			continue
		}
		out = append(out, objs...)
	}
	return out, nil
}

func renderHelm(dir string, opt Options) ([]*model.Object, error) {
	rel := opt.HelmRelease
	if rel == "" {
		rel = "kubeport"
	}
	args := []string{"template", rel, dir}
	for _, v := range opt.HelmValues {
		args = append(args, "-f", v)
	}
	cmd := exec.Command("helm", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("helm template failed: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return parseDocs(out, "helm:"+dir)
}

func renderKustomize(dir string) ([]byte, error) {
	if _, err := exec.LookPath("kustomize"); err == nil {
		return exec.Command("kustomize", "build", dir).Output()
	}
	if _, err := exec.LookPath("kubectl"); err == nil {
		return exec.Command("kubectl", "kustomize", dir).Output()
	}
	if _, err := exec.LookPath("oc"); err == nil {
		return exec.Command("oc", "kustomize", dir).Output()
	}
	return nil, fmt.Errorf("neither kustomize, kubectl nor oc found on PATH")
}

// parseDocs splits a multi-document YAML stream and returns objects that look
// like Kubernetes resources (have apiVersion and kind). List kinds are expanded.
// Each object keeps the raw text of its document so unchanged objects can be
// written back verbatim by `translate`.
func parseDocs(data []byte, source string) ([]*model.Object, error) {
	var out []*model.Object
	for idx, chunk := range SplitDocuments(string(data)) {
		if strings.TrimSpace(stripComments(chunk)) == "" {
			continue
		}
		var doc any
		if err := yaml.Unmarshal([]byte(chunk), &doc); err != nil {
			return nil, fmt.Errorf("%s: document %d: %w", source, idx, err)
		}
		m, ok := normalise(doc).(map[string]any)
		if !ok || m == nil {
			continue
		}
		if m["kind"] == "List" || strings.HasSuffix(model.Str(m["kind"]), "List") {
			if items, ok := m["items"].([]any); ok {
				for _, it := range items {
					if im, ok := it.(map[string]any); ok && im["kind"] != nil {
						out = append(out, &model.Object{Data: im, Source: source, Index: idx})
					}
				}
				continue
			}
		}
		if m["apiVersion"] == nil || m["kind"] == nil {
			continue
		}
		out = append(out, &model.Object{Data: m, Source: source, Index: idx, Raw: chunk})
	}
	return out, nil
}

// SplitDocuments splits a YAML stream on `---` document separators. It is
// intentionally simple: a separator is a line that is exactly `---` (optionally
// followed by whitespace or a comment). Document end markers (`...`) are dropped.
func SplitDocuments(text string) []string {
	var docs []string
	var cur strings.Builder
	for _, line := range strings.SplitAfter(text, "\n") {
		trim := strings.TrimRight(line, "\r\n")
		if trim == "---" || strings.HasPrefix(trim, "--- ") || strings.HasPrefix(trim, "---\t") || strings.HasPrefix(trim, "---#") {
			docs = append(docs, cur.String())
			cur.Reset()
			continue
		}
		if trim == "..." {
			continue
		}
		cur.WriteString(line)
	}
	docs = append(docs, cur.String())
	return docs
}

func stripComments(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

// normalise converts map[any]any (which some decoders emit) into map[string]any.
func normalise(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, vv := range t {
			t[k] = normalise(vv)
		}
		return t
	case map[any]any:
		m := make(map[string]any, len(t))
		for k, vv := range t {
			m[fmt.Sprint(k)] = normalise(vv)
		}
		return m
	case []any:
		for i := range t {
			t[i] = normalise(t[i])
		}
		return t
	}
	return v
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
