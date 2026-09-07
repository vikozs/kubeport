package translate

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/kubeport/kubeport/internal/model"
)

// key order used when re-serialising a modified object. Unlisted keys follow
// alphabetically. This keeps diffs readable and matches how people write YAML.
var topOrder = []string{"apiVersion", "kind", "metadata", "spec", "data", "stringData", "type", "rules", "subjects", "roleRef", "parameters", "objects", "status"}
var metaOrder = []string{"name", "namespace", "labels", "annotations"}
var specOrder = []string{"schedule", "concurrencyPolicy", "suspend", "replicas", "selector", "strategy", "serviceName", "template", "volumeClaimTemplates", "host", "path", "to", "port", "ingressClassName", "tls", "rules", "type", "ports", "accessModes", "storageClassName", "resources", "serviceAccountName", "securityContext", "initContainers", "containers", "volumes"}
var containerOrder = []string{"name", "image", "imagePullPolicy", "command", "args", "env", "envFrom", "ports", "resources", "volumeMounts", "livenessProbe", "readinessProbe", "startupProbe", "securityContext"}
var tlsOrder = []string{"termination", "insecureEdgeTerminationPolicy", "hosts", "secretName"}

// defaultOrder applies to any map without a specific order: name-like keys first.
var defaultOrder = []string{"name", "kind", "apiVersion", "namespace", "type", "path", "pathType", "mountPath", "backend"}

func ordered(v any, order []string) any {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		if order == nil {
			order = defaultOrder
		}
		rank := map[string]int{}
		for i, k := range order {
			rank[k] = i
		}
		sort.Slice(keys, func(i, j int) bool {
			ri, oki := rank[keys[i]]
			rj, okj := rank[keys[j]]
			switch {
			case oki && okj:
				return ri < rj
			case oki:
				return true
			case okj:
				return false
			}
			return keys[i] < keys[j]
		})
		ms := make(yaml.MapSlice, 0, len(keys))
		for _, k := range keys {
			var child []string
			switch k {
			case "metadata":
				child = metaOrder
			case "spec", "template", "jobTemplate":
				child = specOrder
			case "containers", "initContainers":
				child = containerOrder
			case "tls":
				child = tlsOrder
			}
			ms = append(ms, yaml.MapItem{Key: k, Value: ordered(t[k], child)})
		}
		return ms
	case []any:
		out := make([]any, len(t))
		for i := range t {
			out[i] = ordered(t[i], order) // list items inherit the list's order (containers[], tls[])
		}
		return out
	}
	return v
}

// Marshal serialises one object with canonical key ordering.
func Marshal(o *model.Object) ([]byte, error) {
	if md, ok := o.Data["metadata"].(map[string]any); ok {
		for _, k := range []string{"annotations", "labels"} {
			if m, ok := md[k].(map[string]any); ok && len(m) == 0 {
				delete(md, k)
			}
		}
	}
	return yaml.MarshalWithOptions(ordered(o.Data, topOrder), yaml.IndentSequence(true), yaml.UseLiteralStyleIfMultiline(true))
}

// Render produces the full text of a source file after translation: unchanged
// objects keep their original text, changed ones are re-serialised.
func Render(objs []*model.Object, modified map[*model.Object]bool) (string, error) {
	var parts []string
	for _, o := range objs {
		if o.Raw != "" && !modified[o] {
			parts = append(parts, strings.TrimRight(o.Raw, "\n")+"\n")
			continue
		}
		b, err := Marshal(o)
		if err != nil {
			return "", fmt.Errorf("%s: %w", o.Ref(), err)
		}
		parts = append(parts, leadingComments(o.Raw)+string(b))
	}
	return strings.Join(parts, "---\n"), nil
}

// FileOutput is the rendered result for one source.
type FileOutput struct {
	Source  string
	Path    string // where it would be written
	Before  string
	After   string
	Changed bool
}

// RenderAll groups objects by source and renders each. For non-file sources
// (stdin, helm:, kustomize:) Path is "<outDir>/<basename>.yaml".
func RenderAll(objs []*model.Object, modified map[*model.Object]bool, outDir string) ([]FileOutput, error) {
	bySource := map[string][]*model.Object{}
	var order []string
	for _, o := range objs {
		if _, ok := bySource[o.Source]; !ok {
			order = append(order, o.Source)
		}
		bySource[o.Source] = append(bySource[o.Source], o)
	}
	var out []FileOutput
	for _, src := range order {
		group := bySource[src]
		changed := false
		for _, o := range group {
			if modified[o] {
				changed = true
			}
		}
		if !changed {
			continue
		}
		after, err := Render(group, modified)
		if err != nil {
			return nil, err
		}
		fo := FileOutput{Source: src, After: after, Changed: true}
		if isFile(src) {
			fo.Path = src
			if outDir != "" {
				fo.Path = outDir + "/" + baseName(src)
			}
			if b, err := os.ReadFile(src); err == nil {
				fo.Before = string(b)
			}
		} else {
			name := strings.NewReplacer(":", "-", "/", "-", "\\", "-", ".", "-").Replace(src)
			if outDir == "" {
				outDir = "."
			}
			fo.Path = outDir + "/" + strings.Trim(name, "-") + ".yaml"
		}
		out = append(out, fo)
	}
	return out, nil
}

// leadingComments returns the comment/blank lines at the top of a document so
// a re-serialised object keeps its header comment.
func leadingComments(raw string) string {
	var sb strings.Builder
	for _, line := range strings.SplitAfter(raw, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			sb.WriteString(line)
			continue
		}
		break
	}
	return strings.TrimLeft(sb.String(), "\n")
}

func isFile(src string) bool {
	return !strings.HasPrefix(src, "helm:") && !strings.HasPrefix(src, "kustomize:") && src != "stdin" && !strings.HasPrefix(src, "template:")
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// UnifiedDiff returns a minimal unified diff of two texts (LCS on lines).
func UnifiedDiff(name, a, b string) string {
	al := strings.Split(strings.TrimRight(a, "\n"), "\n")
	bl := strings.Split(strings.TrimRight(b, "\n"), "\n")
	if a == "" {
		al = nil
	}
	// LCS table.
	n, m := len(al), len(bl)
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if al[i] == bl[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}
	type op struct {
		kind byte // ' ', '-', '+'
		text string
	}
	var ops []op
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case al[i] == bl[j]:
			ops = append(ops, op{' ', al[i]})
			i++
			j++
		case dp[i+1][j] >= dp[i][j+1]:
			ops = append(ops, op{'-', al[i]})
			i++
		default:
			ops = append(ops, op{'+', bl[j]})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, op{'-', al[i]})
	}
	for ; j < m; j++ {
		ops = append(ops, op{'+', bl[j]})
	}
	// Group changed ops into hunks: consecutive changes closer than 2*ctx
	// lines share a hunk; each hunk gets ctx lines of context on both sides.
	const ctx = 3
	type hunk struct{ start, end int } // op index range [start,end)
	var hunks []hunk
	for k := 0; k < len(ops); k++ {
		if ops[k].kind == ' ' {
			continue
		}
		if len(hunks) > 0 && k-hunks[len(hunks)-1].end <= 2*ctx {
			hunks[len(hunks)-1].end = k + 1
		} else {
			hunks = append(hunks, hunk{k, k + 1})
		}
	}
	var sb strings.Builder
	name = strings.TrimPrefix(name, "/")
	fmt.Fprintf(&sb, "--- a/%s\n+++ b/%s\n", name, name)
	ai, bi := 1, 1 // 1-based line numbers in a and b at op index `pos`
	pos := 0
	advance := func(to int) {
		for ; pos < to; pos++ {
			switch ops[pos].kind {
			case ' ':
				ai++
				bi++
			case '-':
				ai++
			case '+':
				bi++
			}
		}
	}
	for _, h := range hunks {
		start := h.start - ctx
		if start < 0 {
			start = 0
		}
		end := h.end + ctx
		if end > len(ops) {
			end = len(ops)
		}
		advance(start)
		aCount, bCount := 0, 0
		for idx := start; idx < end; idx++ {
			switch ops[idx].kind {
			case ' ':
				aCount++
				bCount++
			case '-':
				aCount++
			case '+':
				bCount++
			}
		}
		fmt.Fprintf(&sb, "@@ -%d,%d +%d,%d @@\n", ai, aCount, bi, bCount)
		for idx := start; idx < end; idx++ {
			sb.WriteByte(ops[idx].kind)
			sb.WriteString(ops[idx].text)
			sb.WriteByte('\n')
		}
		advance(end)
	}
	return sb.String()
}
