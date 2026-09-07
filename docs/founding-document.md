# Kubeport · Founding Document

**Status:** Draft v0.1 · September 2026
**Type:** Open-source community tool (Apache-2.0)
**One line:** A portability linter and translator for Kubernetes workloads. Point it at your manifests, tell it where they run today and where they need to run tomorrow (k3s, vanilla Kubernetes, OpenShift), and it tells you exactly what breaks and rewrites what it safely can.

---

## 1. Why this exists

The Kubernetes ecosystem quietly fragmented. The API is the same everywhere; the *contract around it* is not.

- **k3s** ships Traefik, ServiceLB (Klipper), local-path-provisioner, an embedded SQLite/etcd, and permissive defaults. Things "just work" on a Raspberry Pi and silently rely on all of it.
- **Vanilla Kubernetes** (kubeadm, EKS, GKE, AKS, Talos) has no default Ingress controller, Pod Security Admission instead of PSP, and per-provider StorageClasses and LoadBalancer semantics.
- **OpenShift** adds Security Context Constraints (restricted-v2 by default), arbitrary UIDs, Routes alongside Ingress, ImageStreams, the OpenShift Router, integrated OAuth, and a stricter view of `hostPath`, `privileged` and `runAsUser: 0`.

The result is a recurring, expensive pattern: a workload is developed on k3s, tested on kind or a managed cluster, and dies on the first `oc apply` into a regulated OpenShift environment with `unable to validate against any security context constraint`. Or the reverse: an OpenShift-native chart full of `Route` objects and `anyuid` assumptions is handed to a team on k3s at the edge.

Today this gap is closed by tribal knowledge, Stack Overflow, and a senior engineer reading YAML line by line. Existing tools do not cover it:

| Tool | What it does | What it misses |
|---|---|---|
| kubent, Pluto | Deprecated API versions per Kubernetes release | Nothing about distribution differences |
| kubeconform, kubeval | Schema validation against upstream OpenAPI | OpenShift CRDs, SCC semantics, k3s add-ons |
| Polaris, kube-score, kube-linter | Best-practice checks | Not target-aware; "add securityContext" is not "this fails restricted-v2" |
| Kyverno / Gatekeeper | Runtime admission policy | Runs in the cluster, after the fact, only for that cluster |
| Helm `--dry-run`, `oc process` | Rendering | No cross-target analysis |

Kubeport is the missing build-time step: **distribution-aware, version-aware, and able to fix as well as flag.**

## 2. What Kubeport is

A single static binary (`kubeport`) plus a rules repository, usable as:

1. **CLI** for developers: `kubeport check --from k3s --to openshift:4.19 ./chart`
2. **CI gate**: GitHub Action, GitLab CI template, Tekton Task; non-zero exit on blocking findings, SARIF output for code scanning.
3. **Pre-commit hook** and **kubectl/oc plugin** (`kubectl port`, `oc port`).
4. **Translator**: `kubeport translate` rewrites manifests for the target where a safe, deterministic mapping exists, emitting a diff and leaving everything else untouched with an inline `# kubeport: manual` comment.
5. **Badge**: `kubeport badge` produces a compatibility matrix for OSS project READMEs (tested on k3s 1.31, k8s 1.30–1.32, OpenShift 4.17–4.19).

### Inputs

Raw YAML directories, Helm charts (rendered with values, optionally multiple values files), Kustomize overlays, OpenShift Templates, and `kubectl get -o yaml` dumps of a live namespace (so an existing cluster can be audited before a migration).

### Targets

A target is `distribution:version` with an optional profile: `k3s:1.31`, `k8s:1.32`, `k8s:1.32/eks`, `openshift:4.19`, `openshift:4.19/hosted`. Profiles carry provider quirks (EKS ALB annotations, GKE Autopilot restrictions, ROSA/ARO differences). Users can define custom profiles for their own clusters (`--profile ./zav-prod.yaml`), which is how a platform team encodes "our cluster has these StorageClasses, this Ingress class, these SCCs bound".

## 3. What it checks (initial rule catalogue)

Rules are grouped by domain. Each rule has a severity per target (a rule can be `error` on OpenShift and `info` on k3s), a link to the relevant upstream doc, and, where possible, an autofix.

**Security context and admission**
- `sec/run-as-root` · `runAsUser: 0` or no `runAsNonRoot` → fails restricted-v2 SCC; fails PSA `restricted`.
- `sec/fixed-uid` · Hard-coded UID that is not in the namespace's assigned range → OpenShift arbitrary-UID conflict. Autofix: drop `runAsUser`, keep `runAsNonRoot: true`, add `fsGroup` guidance.
- `sec/capabilities` · Missing `drop: [ALL]`, or requesting `NET_RAW`, `SYS_ADMIN`.
- `sec/privileged`, `sec/host-namespaces`, `sec/hostpath` · Per-target severity.
- `sec/seccomp-profile` · Missing `RuntimeDefault` where PSA `restricted` requires it.
- `sec/psp-usage` · `PodSecurityPolicy` objects (removed in 1.25).
- `sec/scc-annotation` · OpenShift-only `openshift.io/scc` references present when targeting k3s or k8s.

**Networking**
- `net/route-on-non-openshift` · `route.openshift.io/v1` Route targeting k3s/k8s. Autofix: Route → Ingress (host, path, TLS termination edge/passthrough mapped where possible; re-encrypt flagged manual).
- `net/ingress-on-openshift` · Ingress with a class OpenShift cannot serve, or Traefik-specific annotations (`traefik.ingress.kubernetes.io/*`). Autofix: Ingress → Route when semantics are preserved.
- `net/ingress-class-missing` · No `ingressClassName` on a target with no default class.
- `net/servicelb-assumption` · `type: LoadBalancer` relying on Klipper ServiceLB behaviour (node-port passthrough) on a target without an LB implementation.
- `net/network-policy-default` · Target has default-deny (OpenShift Networking profile) and the workload defines no NetworkPolicy.

**Storage**
- `stor/storageclass-missing` · Referenced StorageClass not present in the target profile. Autofix from a mapping table (`local-path` → `gp3`, `thin-csi`, `ocs-storagecluster-ceph-rbd`).
- `stor/local-path-rwx` · `ReadWriteMany` on local-path (k3s) which does not support it.
- `stor/hostpath-volume` · Per-target severity; blocked on OpenShift restricted-v2.

**Images and registries**
- `img/imagestream-on-non-openshift` · ImageStream / `image.openshift.io` references.
- `img/internal-registry` · `image-registry.openshift-image-registry.svc` or `docker.io` short names where the target has different mirror/registry policy.
- `img/latest-tag` · Informational everywhere.

**API and version compatibility**
- `api/deprecated`, `api/removed` · Per target Kubernetes minor (OpenShift versions map to their bundled Kubernetes minor: 4.19 → 1.32).
- `api/crd-missing` · CRD kinds used (Prometheus Operator, cert-manager, Traefik IngressRoute, OpenShift Console plugins) not present in the target profile.

**Platform-specific objects**
- `ocp/template-object` · OpenShift Template targeting k3s/k8s. Autofix: render to plain manifests with parameters as a values file.
- `ocp/oauth-proxy`, `ocp/service-ca` · `service.beta.openshift.io/serving-cert-secret-name` annotations without equivalent (flag, suggest cert-manager).
- `k3s/traefik-crd` · `IngressRoute`, `Middleware` on non-k3s targets.

**Resource hygiene (target-aware)**
- `res/limits-missing` · Error on OpenShift projects with LimitRange/ResourceQuota in profile, info elsewhere.
- `res/quota-exceeded` · Sum of requests against ResourceQuota in profile.

The catalogue is a directory of YAML rule files with a Rego or CEL condition, so contributors do not need to touch Go to add a rule.

## 4. What Kubeport is not (non-goals for v1)

- Not a runtime admission controller. It complements Kyverno/Gatekeeper; it does not replace them.
- Not a generic best-practice linter. If a finding is not about *portability between targets or versions*, it belongs in kube-score or Polaris.
- Not a Helm chart generator or a GitOps engine.
- Not a cluster scanner or CSPM tool. It reads manifests and, optionally, a namespace dump; it never needs cluster-admin.
- Not a monitoring tool (see PocketShift, an unrelated project).

## 5. Architecture

```
kubeport (Go, single static binary, cosign-signed)
├── loader/       YAML dirs, Helm (via helm SDK), Kustomize (via kustomize API),
│                 OpenShift Templates, live namespace dump
├── model/        Normalised object graph; Pod templates extracted from every
│                 workload kind (Deployment, StatefulSet, DaemonSet, Job, CronJob,
│                 DeploymentConfig, Argo Rollout, Knative Service)
├── targets/      Target + profile definitions (YAML): distribution facts,
│                 bundled k8s minor, default SCC/PSA level, available classes,
│                 CRD inventory, provider quirks
├── rules/        Rule engine (CEL first, Rego optional), severity matrix,
│                 autofix hooks
├── translate/    Deterministic rewriters (Route<->Ingress, Template->manifests,
│                 StorageClass mapping, SCC-safe securityContext)
├── report/       text, JSON, SARIF, JUnit, Markdown badge/matrix
└── cmd/          check, translate, explain <rule>, targets list, profile init
```

Design constraints:

- **Deterministic and offline.** No network calls by default. Target definitions ship with the binary and are versioned; `kubeport targets update` fetches newer ones from the rules repo when explicitly asked.
- **Fast.** Whole Helm chart under one second; suitable for pre-commit.
- **Explainable.** Every finding prints *why* (which SCC field, which PSA level, which removed API) and links to the upstream document. `kubeport explain sec/fixed-uid` gives the long-form.
- **Safe translation.** `translate` only applies rewrites proven semantics-preserving. Anything ambiguous is annotated, never guessed. Output is a diff first, files second (`--write`).
- **Profile as code.** Platform teams publish `profile.yaml` for their clusters; application teams point at it. This is the mechanism by which a regulated platform team (Solvency II, DORA) can express "this is what our cluster accepts" once, and every CI pipeline enforces it before anything reaches the cluster.

Target facts are sourced from: Kubernetes deprecation guide, OpenShift release notes and SCC documentation, k3s docs, and generated CRD inventories from reference installs of each supported version. A nightly job spins up kind, k3d and a CRC/OKD single-node to regenerate inventories and run the conformance suite in section 8.

## 6. User experience

```
$ kubeport check --from k3s:1.31 --to openshift:4.19 ./deploy

kubeport 0.1.0 · 14 objects · k3s:1.31 -> openshift:4.19

ERROR  sec/fixed-uid        Deployment/api  spec.template.spec.securityContext.runAsUser=1000
       OpenShift restricted-v2 assigns UIDs from the project range; a fixed UID
       is rejected. Fix available: kubeport translate --rule sec/fixed-uid
ERROR  stor/storageclass-missing  PVC/data  storageClassName=local-path
       Not present in target. Suggested mapping: thin-csi
WARN   net/ingress-on-openshift   Ingress/api  traefik.ingress.kubernetes.io/router.middlewares
       Annotation ignored by OpenShift Router. Consider Route or HAProxy annotations.
INFO   img/latest-tag       Deployment/api  image=ghcr.io/acme/api:latest

3 findings (2 error, 1 warn, 1 info) · 2 autofixable
exit 1
```

```
$ kubeport translate --to openshift:4.19 ./deploy --write
  modified  deploy/api-deployment.yaml   (sec/fixed-uid: removed runAsUser, kept runAsNonRoot)
  modified  deploy/data-pvc.yaml         (stor/storageclass-missing: local-path -> thin-csi)
  created   deploy/api-route.yaml        (net/ingress-on-openshift: Ingress -> Route, edge TLS)
  manual    deploy/api-ingress.yaml      (traefik middleware has no Route equivalent)
```

GitHub Action:

```yaml
- uses: kubeport/action@v1
  with:
    path: ./chart
    from: k3s:1.31
    to: openshift:4.19,k8s:1.32/eks
    profile: .kubeport/prod-profile.yaml
    fail-on: error
```

## 7. Roadmap

**v0.1 · Proof (3 months)**
- Go CLI, YAML and Helm loaders, 25 rules across sec/net/stor/api, targets k3s 1.31, k8s 1.30–1.32, OpenShift 4.17–4.19.
- Text and JSON output. `explain`. Homebrew and GitHub Releases.
- Dogfood on one real migration end to end.

**v0.2 · CI (2 months)**
- Kustomize and OpenShift Template loaders. SARIF, JUnit. GitHub Action, GitLab template, Tekton Task, pre-commit hook.
- Custom profiles (`profile init` reads a live cluster with read-only RBAC and emits `profile.yaml`).

**v0.3 · Translate (3 months)**
- Deterministic rewriters: Route ↔ Ingress, Template → manifests, StorageClass mapping, SCC-safe securityContext.
- `kubectl`/`oc` plugin via Krew.

**v0.4 · Community**
- Badge and compatibility matrix generator. Public registry of profiles for common managed offerings (EKS, GKE, AKS, ROSA, ARO, k3s on Raspberry Pi, Talos).
- Rule contributions from at least five external maintainers.

**v1.0**
- Stable rule IDs and output schema. Conformance suite green across all supported targets. Nightly target inventory regeneration. CNCF Sandbox application.

## 8. Quality and trust

- **Conformance suite:** a corpus of real-world charts (Bitnami, Prometheus Operator, ArgoCD, Keycloak, GitLab, Grafana, Harbor, plus deliberately broken fixtures). Every rule must have a positive and negative fixture. Every autofix must re-check clean against the target and must `kubectl apply --dry-run=server` cleanly on the real target in the nightly job.
- **False positive budget:** a rule with more than 5 % false positives on the corpus is demoted to `info` until fixed. Portability tools die from noise faster than from gaps.
- **Supply chain:** SLSA level 3 builds, cosign signatures, SBOM per release, reproducible builds.
- **Versioning:** target definitions and rules are versioned independently from the binary (`kubeport version` shows both). Rule IDs never change meaning; deprecated rules are aliased, not repurposed.

## 9. Governance and community

- **License:** Apache-2.0 for code; CC-BY-4.0 for rule documentation. No CLA, DCO sign-off only.
- **Repo:** `github.com/kubeport/kubeport` (name subject to trademark and namespace check before announcement; fallbacks: `portakube`, `shiftcheck`, `k8sport`).
- **Governance:** single maintainer at start with a written path to a maintainer team after v0.4 (two external maintainers with merge rights, decisions by lazy consensus, public roadmap board). Adopt the CNCF Code of Conduct from day one.
- **Contribution surface designed for non-Go contributors:** rules are YAML + CEL, target facts are YAML, fixtures are plain manifests. A first-time contributor can add a rule with a test in under an hour; that is the bar.
- **Vendor neutrality:** treat k3s, upstream and OpenShift symmetrically. A rule that fires only against OpenShift must have a mirror consideration for the other direction. Red Hat, SUSE/Rancher, and cloud providers are invited to own their target definitions but no vendor owns the project.
- **Channels:** GitHub Discussions, a `#kubeport` channel on the Kubernetes Slack, monthly community call once there are three regular contributors. Announce in r/kubernetes, r/openshift, the k3s Discussions board, and KubeCon EU 2027 CFP (lightning talk: "Your chart works on k3s. Here is why it dies on OpenShift.").

## 10. Success criteria

| Horizon | Signal |
|---|---|
| 6 months | 1 000 GitHub stars, 20 external issues that are real portability cases, used in CI by 10 public repos |
| 12 months | 3 external maintainers, 100 rules, profiles for 8 managed offerings, one upstream OSS project (e.g. a popular Helm chart repo) adds the badge |
| 24 months | CNCF Sandbox accepted, referenced in OpenShift or k3s migration documentation, `kubeport` appears in "how do I make this run on OpenShift" answers instead of a wall of YAML |

## 11. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Rule noise erodes trust | False positive budget (section 8); severity is per target, not global; `info` by default for anything not proven blocking |
| Target facts go stale (new OpenShift every 4 months) | Nightly inventory regeneration against real installs; target definitions are data, updateable without a binary release |
| Perceived as anti-OpenShift or anti-k3s | Symmetric rules, vendor-neutral governance, invite vendors to own their target files |
| Autofix silently changes behaviour | Only deterministic, semantics-preserving rewrites; everything else annotated; diff-first UX; server dry-run in tests |
| Solo maintainer burnout | Non-Go contribution surface, explicit maintainer-team path, scope discipline (section 4) |
| Name collision | Check npm, PyPI, Go module path, Docker Hub, trademark databases before announcement; fallbacks listed |

## 12. Founder fit and first steps

The founder runs OpenShift in a regulated insurance environment (Solvency II, GDPR, DORA) and hits this problem from the receiving end: workloads and charts built elsewhere arriving at a cluster with restricted-v2, quotas and a strict registry policy. The first custom profile will be a real production profile, which is the strongest possible test of the profile-as-code idea.

Next 14 days:

1. Name and namespace check; reserve GitHub org, Go module path, Homebrew tap.
2. Scaffold the Go project: loader for plain YAML, model extraction for Pod templates, CEL rule engine, five rules (`sec/run-as-root`, `sec/fixed-uid`, `net/route-on-non-openshift`, `stor/storageclass-missing`, `api/removed`).
3. Write target files for `k3s:1.31`, `k8s:1.32`, `openshift:4.19` by hand.
4. Run against three public charts and one internal workload; record every false positive.
5. Publish v0.0.1 with a README that leads with the terminal output in section 6.
