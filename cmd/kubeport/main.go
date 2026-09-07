// kubeport: a portability linter and translator for Kubernetes workloads
// moving between k3s, upstream Kubernetes and OpenShift.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kubeport/kubeport/internal/catalog"
	"github.com/kubeport/kubeport/internal/loader"
	"github.com/kubeport/kubeport/internal/model"
	"github.com/kubeport/kubeport/internal/report"
	"github.com/kubeport/kubeport/internal/rules"
	"github.com/kubeport/kubeport/internal/targets"
	"github.com/kubeport/kubeport/internal/translate"
)

// version is set by the build (-ldflags "-X main.version=...").
var version = "dev"

const usage = `kubeport · portability linter and translator for Kubernetes workloads

Usage:
  kubeport check     [flags] <path|chart|dir|->...   report what breaks on the target(s)
  kubeport translate [flags] <path|chart|dir|->...   rewrite what can be rewritten, print a diff
  kubeport explain   <rule-id>                       long-form explanation of a rule
  kubeport rules                                     list rules
  kubeport targets                                   list shipped targets and profiles
  kubeport profile init [--extends k8s:1.32]         write a starter cluster profile
  kubeport version

Targets are <distribution>:<version>[/profile], e.g. k3s:1.31, k8s:1.32/eks,
openshift:4.19/vsphere, or a path to your own profile YAML.

Examples:
  kubeport check --from k3s:1.31 --to openshift:4.19 ./deploy
  kubeport check --to openshift:4.19,k8s:1.32/eks --format sarif ./chart > kubeport.sarif
  helm template app ./chart | kubeport check --to openshift:4.19 -
  kubeport translate --to openshift:4.19/vsphere ./deploy --write
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	code := 0
	switch os.Args[1] {
	case "check":
		code, err = cmdCheck(os.Args[2:])
	case "translate":
		code, err = cmdTranslate(os.Args[2:])
	case "explain":
		err = cmdExplain(os.Args[2:])
	case "rules":
		cmdRules()
	case "targets":
		err = cmdTargets()
	case "profile":
		err = cmdProfile(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("kubeport", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "kubeport: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "kubeport:", err)
		os.Exit(2)
	}
	os.Exit(code)
}

type common struct {
	from, to      string
	helmValues    multi
	release       string
	noRender      bool
	disable, only multi
}

func (c *common) bind(fs *flag.FlagSet) {
	fs.StringVar(&c.from, "from", "", "where the manifests run today (context for messages), e.g. k3s:1.31")
	fs.StringVar(&c.to, "to", "", "target(s), comma-separated, e.g. openshift:4.19,k8s:1.32/eks (required)")
	fs.Var(&c.helmValues, "values", "Helm values file (repeatable)")
	fs.Var(&c.helmValues, "f", "Helm values file (repeatable, short)")
	fs.StringVar(&c.release, "release", "kubeport", "Helm release name used for rendering")
	fs.BoolVar(&c.noRender, "no-render", false, "treat Helm charts and kustomizations as plain YAML directories")
	fs.Var(&c.disable, "disable", "rule id to skip (repeatable, or comma-separated)")
	fs.Var(&c.only, "rule", "run only this rule id (repeatable, or comma-separated)")
}

func (c *common) load(paths []string) (*model.Bundle, []*targets.Target, *targets.Target, error) {
	if len(paths) == 0 {
		return nil, nil, nil, fmt.Errorf("no input given (a directory, file, chart or - for stdin)")
	}
	if c.to == "" {
		return nil, nil, nil, fmt.Errorf("--to is required (see `kubeport targets`)")
	}
	tos, err := targets.ResolveAll(c.to)
	if err != nil {
		return nil, nil, nil, err
	}
	var from *targets.Target
	if c.from != "" {
		if from, err = targets.Resolve(c.from); err != nil {
			return nil, nil, nil, err
		}
	}
	b, err := loader.Load(paths, loader.Options{HelmValues: c.helmValues, HelmRelease: c.release, NoRender: c.noRender})
	if err != nil {
		return nil, nil, nil, err
	}
	return b, tos, from, nil
}

func (c *common) ruleOptions() rules.Options {
	return rules.Options{Disable: set(c.disable), Only: set(c.only)}
}

func runAll(b *model.Bundle, tos []*targets.Target, from *targets.Target, opt rules.Options, inputs []string) report.Run {
	r := report.Run{Version: version, Inputs: inputs, Objects: len(b.Objects)}
	if from != nil {
		r.From = from.ID()
	}
	for _, t := range tos {
		fs := rules.Run(&rules.Context{From: from, To: t, Bundle: b}, opt)
		r.Results = append(r.Results, report.TargetResult{Target: t, TargetID: t.ID(), Display: t.Display, Findings: fs, Summary: rules.Summarise(fs)})
	}
	return r
}

func cmdCheck(args []string) (int, error) {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	var c common
	c.bind(fs)
	format := fs.String("format", "text", "text | json | sarif | matrix | badge")
	failOn := fs.String("fail-on", "error", "exit 1 when a finding of this severity or higher exists: error | warn | info | none")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: kubeport check [flags] <path>...")
		fs.PrintDefaults()
	}
	paths, err := parseInterspersed(fs, args)
	if err != nil {
		return 2, nil
	}
	b, tos, from, err := c.load(paths)
	if err != nil {
		return 2, err
	}
	run := runAll(b, tos, from, c.ruleOptions(), paths)

	switch *format {
	case "text":
		report.Text(os.Stdout, run)
	case "json":
		if err := report.JSON(os.Stdout, run); err != nil {
			return 2, err
		}
	case "sarif":
		if err := report.SARIF(os.Stdout, run); err != nil {
			return 2, err
		}
	case "matrix", "markdown", "md":
		report.Matrix(os.Stdout, run)
	case "badge":
		if err := report.Badge(os.Stdout, run); err != nil {
			return 2, err
		}
	default:
		return 2, fmt.Errorf("unknown --format %q", *format)
	}

	if *failOn == "none" {
		return 0, nil
	}
	threshold, ok := rules.ParseSeverity(*failOn)
	if !ok {
		return 2, fmt.Errorf("unknown --fail-on %q", *failOn)
	}
	for _, tr := range run.Results {
		if len(tr.Findings) > 0 && rules.Max(tr.Findings) >= threshold {
			return 1, nil
		}
	}
	return 0, nil
}

func cmdTranslate(args []string) (int, error) {
	fs := flag.NewFlagSet("translate", flag.ContinueOnError)
	var c common
	c.bind(fs)
	write := fs.Bool("write", false, "write the rewritten files in place (or into --output)")
	outDir := fs.String("output", "", "directory to write results into instead of editing in place")
	quiet := fs.Bool("quiet", false, "do not print the diff")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: kubeport translate [flags] <path>...")
		fs.PrintDefaults()
	}
	paths, err := parseInterspersed(fs, args)
	if err != nil {
		return 2, nil
	}
	b, tos, from, err := c.load(paths)
	if err != nil {
		return 2, err
	}
	if len(tos) != 1 {
		return 2, fmt.Errorf("translate needs exactly one --to target")
	}
	to := tos[0]
	findings := rules.Run(&rules.Context{From: from, To: to, Bundle: b}, c.ruleOptions())
	res := translate.Apply(b, to, findings, set(c.only))

	files, err := translate.RenderAll(b.Objects, res.Modified, *outDir)
	if err != nil {
		return 2, err
	}
	if len(res.Changes) == 0 {
		fmt.Println("kubeport: nothing to translate for", to.ID())
		return 0, nil
	}
	fmt.Printf("kubeport %s · translate -> %s\n\n", version, to.ID())
	for _, ch := range res.Changes {
		fmt.Printf("  %-34s %-28s %s\n", ch.Object, ch.Rule, ch.Description)
	}
	if len(res.Notes) > 0 {
		fmt.Println("\n  manual follow-up:")
		for _, n := range res.Notes {
			fmt.Printf("  - %s [%s]: %s\n", n.Object, n.Rule, n.Message)
		}
	}
	if !*quiet {
		fmt.Println()
		for _, f := range files {
			fmt.Print(translate.UnifiedDiff(f.Path, f.Before, f.After))
		}
	}
	if *write {
		for _, f := range files {
			if err := os.MkdirAll(filepath.Dir(f.Path), 0o755); err != nil {
				return 2, err
			}
			if err := os.WriteFile(f.Path, []byte(f.After), 0o644); err != nil {
				return 2, err
			}
			fmt.Println("  wrote", f.Path)
		}
	} else {
		fmt.Println("\n  (dry run: add --write to apply)")
	}
	// Re-check so the user sees what is left.
	left := rules.Run(&rules.Context{From: from, To: to, Bundle: b}, c.ruleOptions())
	s := rules.Summarise(left)
	fmt.Printf("\n  after translation: %d error, %d warn, %d info remaining for %s\n", s.Errors, s.Warnings, s.Infos, to.ID())
	return 0, nil
}

func cmdExplain(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: kubeport explain <rule-id>")
	}
	meta, ok := catalog.Rule(args[0])
	if !ok {
		return fmt.Errorf("unknown rule %q (see `kubeport rules`)", args[0])
	}
	fmt.Printf("%s\n%s\n\n%s\n", meta.ID, meta.Title, meta.Summary)
	if d := strings.TrimSpace(meta.Detail); d != "" {
		fmt.Printf("\n%s\n", d)
	}
	if meta.Fix != "" {
		fmt.Printf("\nautofix: %s\n", meta.Fix)
	} else {
		fmt.Printf("\nautofix: none (needs a human decision)\n")
	}
	if meta.Docs != "" {
		fmt.Printf("docs:    %s\n", meta.Docs)
	}
	return nil
}

func cmdRules() {
	impl := map[string]bool{}
	for _, id := range rules.IDs() {
		impl[id] = true
	}
	for _, m := range catalog.Rules() {
		fix := " "
		if m.Fix != "" {
			fix = "F"
		}
		if !impl[m.ID] {
			fix = "?"
		}
		fmt.Printf("%s %-36s %s\n", fix, m.ID, m.Title)
	}
	fmt.Println("\nF = autofix available")
}

func cmdTargets() error {
	list, err := targets.List()
	if err != nil {
		return err
	}
	fmt.Printf("%-16s %-8s %-70s %s\n", "TARGET", "K8S", "DESCRIPTION", "PROFILES")
	for _, e := range list {
		fmt.Printf("%-16s %-8s %-70s %s\n", e.ID, e.Kubernetes, e.Display, strings.Join(e.Profiles, ", "))
	}
	fmt.Println("\nUse <target>/<profile>, e.g. openshift:4.19/vsphere, or --to ./my-cluster.yaml (see `kubeport profile init`).")
	return nil
}

func cmdProfile(args []string) error {
	if len(args) == 0 || args[0] != "init" {
		return fmt.Errorf("usage: kubeport profile init [--extends <target>] [--out profile.yaml]")
	}
	fs := flag.NewFlagSet("profile init", flag.ContinueOnError)
	extends := fs.String("extends", "openshift:4.19", "base target the profile refines")
	out := fs.String("out", "kubeport-profile.yaml", "file to write")
	if err := fs.Parse(args[1:]); err != nil {
		return nil
	}
	if _, err := targets.Resolve(*extends); err != nil {
		return err
	}
	if err := os.WriteFile(*out, []byte(targets.ProfileTemplate(*extends)), 0o644); err != nil {
		return err
	}
	fmt.Println("wrote", *out, "· edit it, then: kubeport check --to", *out, "./deploy")
	return nil
}

// parseInterspersed lets flags appear before or after positional arguments
// (`kubeport translate ./deploy --write` works like `--write ./deploy`).
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		i := 0
		for i < len(rest) && !strings.HasPrefix(rest[i], "-") || i < len(rest) && rest[i] == "-" {
			positional = append(positional, rest[i])
			i++
		}
		if i >= len(rest) {
			return positional, nil
		}
		args = rest[i:]
	}
}

// multi is a repeatable, comma-splittable flag.
type multi []string

func (m *multi) String() string { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*m = append(*m, p)
		}
	}
	return nil
}

func set(m multi) map[string]bool {
	if len(m) == 0 {
		return nil
	}
	out := map[string]bool{}
	for _, v := range m {
		out[v] = true
	}
	return out
}
