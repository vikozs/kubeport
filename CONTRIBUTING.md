# Contributing to Kubeport

Thanks for helping people move workloads between k3s, Kubernetes and OpenShift without a weekend of YAML archaeology.

## The one-hour contribution

Most valuable contributions do not touch Go:

**A new target or profile.** Copy the closest file in `internal/targets/data/<distribution>/` and edit the facts. A profile (`.../profiles/<name>.yaml`) only lists what differs from the base. Add a fixture exercising the difference if you can. Run `make test`.

**A new rule.** Three parts:
1. Metadata in `internal/catalog/rules.yaml` (id, title, summary, detail, docs, fix). Ids are `category/kebab-name` and are never renamed or reused.
2. The check in `internal/rules/` (`security.go` or `platform.go`). Severity is decided per target from `Context`: `c.Strict()`, `c.To.HostPathAllowed`, `c.To.HasAPIGroup(...)` and so on. A rule that fires the same way on every target probably belongs in kube-score, not here.
3. A positive fixture (fires) and a negative one (does not) under `fixtures/`, plus an assertion in `internal/rules/rules_test.go`. `TestEveryRuleHasCatalogEntry` will fail until the metadata exists.

**An autofix.** Only when the rewrite is deterministic and preserves behaviour. Add a case in `internal/translate/translate.go`, mark the finding `fixable` in the rule, and add a round-trip test: apply, re-run rules, assert the finding is gone and nothing new appeared. When in doubt, emit a `Note` instead of guessing.

**A false positive.** Open an issue with the manifest (redacted is fine) and the target. Rules over the 5 % false-positive budget on the fixture corpus get demoted to `info` until fixed.

## Ground rules

- Symmetry: a rule that only ever fires against OpenShift needs a written reason why the reverse direction does not apply.
- Every finding says *why* and links to upstream documentation, not to a blog post.
- Messages are one or two sentences, name the field, and say what to do.
- No em-dashes in prose (house style); use a colon, comma or middot.
- Commits need a DCO sign-off (`git commit -s`). No CLA.

## Development

```
make build     # bin/kubeport
make test
make lint      # gofmt + go vet
make fixtures  # run every fixture against three target families
```

Go 1.22+ and no dependencies beyond `github.com/goccy/go-yaml`. Keep it that way unless the dependency buys something the whole project needs.
