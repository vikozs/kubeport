# kubeport

**Your chart works on k3s. Here is why it dies on OpenShift.** Kubeport is a portability linter and translator for Kubernetes workloads. Tell it where the manifests run today and where they need to run next (k3s, upstream Kubernetes, OpenShift, or your own cluster profile) and it reports exactly what breaks, then rewrites what can be rewritten safely.

```
$ kubeport check --from k3s:1.31 --to openshift:4.19/vsphere ./deploy

kubeport 0.1.0 · 5 objects · k3s:1.31 -> openshift:4.19/vsphere
ERROR  sec/fixed-uid                    Deployment/api  spec.template.spec.securityContext.runAsUser
       pod pins runAsUser=1000; restricted-v2 assigns UIDs from the project range and rejects fixed
       UIDs outside it
       fix available: kubeport translate --to openshift:4.19/vsphere --rule sec/fixed-uid
ERROR  sec/hostpath                     Deployment/api  spec.template.spec.volumes[1].hostPath
       volume "docker" mounts host path /var/run/docker.sock; refused by SCC restricted-v2
ERROR  stor/storageclass-missing        PersistentVolumeClaim/api-data  spec.storageClassName
       claim "api-data" uses StorageClass "local-path" which OpenShift 4.19 (vSphere, thin-csi) does
       not have; suggested: thin-csi
       fix available: kubeport translate --to openshift:4.19/vsphere --rule stor/storageclass-missing
WARN   net/ingress-on-openshift         Ingress/api  metadata.annotations
       2 annotation(s) for another Ingress controller are ignored by OpenShift 4.19 (vSphere, thin-csi):
       traefik.ingress.kubernetes.io/router.middlewares, ... The OpenShift Router serves the Ingress but
       drops these; behaviour such as rewrites, middlewares or rate limits is lost
INFO   img/latest-tag                   Deployment/api  spec.template.spec.containers[0].image
       container "api" image "ghcr.io/acme/api:latest" has no pinned tag

11 finding(s) (7 error, 3 warn, 1 info) · 7 autofixable · kubeport explain <rule> for details
```

```
$ kubeport translate --to openshift:4.19/vsphere ./deploy --write

  Deployment/api                 sec/fixed-uid               removed pod.runAsUser, pod.fsGroup; kept runAsNonRoot=true
  Deployment/api                 sec/capabilities            added capabilities.drop [ALL] to api
  PersistentVolumeClaim/api-data stor/storageclass-missing   spec: storageClassName local-path -> thin-csi
  Ingress/api                    net/ingress-on-openshift    converted Ingress to route.openshift.io/v1 Route Route/api

  manual follow-up:
  - Ingress/api: dropped controller annotations with no Route equivalent: traefik.ingress.kubernetes.io/router.middlewares ...

  after translation: 3 error, 0 warn, 1 info remaining for openshift:4.19/vsphere
```

Existing tools check API deprecations (kubent, Pluto), schemas (kubeconform) or best practices (kube-score, Polaris). None of them know that `runAsUser: 1000` is fine on k3s and fatal on OpenShift, that `local-path` does not exist on EKS, or that a `Route` cannot be created on kind. Kubeport is the build-time step that does.

## Install

```
# Homebrew (macOS, Linux)
brew install kubeport/tap/kubeport

# Go
go install github.com/kubeport/kubeport/cmd/kubeport@latest

# kubectl / oc plugin
kubectl krew install port      # then: kubectl port check ...

# Binary
curl -fsSL https://github.com/kubeport/kubeport/releases/latest/download/kubeport_linux_amd64.tar.gz | tar xz
```

Windows (PowerShell): download the `windows_amd64.zip` from the releases page, or `go install` as above. Releases are signed with cosign; see the release notes for the verify command.

## What it reads

Plain YAML files and directories, multi-document streams on stdin (`-`), Helm charts (rendered with `helm template` when `helm` is on PATH; `-f values.yaml` is passed through), Kustomize overlays (`kustomize`, `kubectl kustomize` or `oc kustomize`), OpenShift Templates, and `kubectl get -o yaml` dumps of a live namespace.

```
helm template shop ./chart -f prod.yaml | kubeport check --to openshift:4.19 -
kubeport check --to k3s:1.31 ./overlays/edge
kubectl get deploy,svc,ingress,pvc -n shop -o yaml | kubeport check --from k8s:1.32/eks --to openshift:4.19 -
```

## Targets

`<distribution>:<version>[/profile]`. Run `kubeport targets` for the shipped list:

| Distribution | Versions | Profiles |
|---|---|---|
| `k3s` | 1.30 to 1.34 | `rpi`, `hardened` |
| `k8s` (also `kubernetes`, `vanilla`) | 1.29 to 1.34 | `eks`, `gke`, `aks`, `talos` |
| `openshift` (also `ocp`, `okd`) | 4.16 to 4.20 | `vsphere`, `odf`, `rosa`, `aro`, `regulated` |

Facts about each target (admission model, default SCC or PSA level, Ingress controller, LoadBalancer support, StorageClasses, installed API groups) live in YAML under [`internal/targets/data`](internal/targets/data). Adding a version or profile is a pull request with no Go in it.

**Your cluster is a target too.** `kubeport profile init --extends openshift:4.19` writes a profile you fill in with your StorageClasses, Ingress class and CRDs; then `--to ./prod.yaml`. Platform teams publish the profile, application teams point their CI at it. See [docs/profiles.md](docs/profiles.md).

## Rules

`kubeport rules` lists them, `kubeport explain <id>` gives the long form with upstream docs. Severity is decided **per target**: `sec/hostpath` is an error on OpenShift and PSA restricted, informational on default k3s.

| Category | Rules |
|---|---|
| Security context and admission | `sec/run-as-root`, `sec/fixed-uid`, `sec/capabilities`, `sec/allow-privilege-escalation`, `sec/privileged`, `sec/host-namespaces`, `sec/hostpath`, `sec/seccomp-profile`, `sec/psp-usage`, `sec/scc-annotation` |
| Networking | `net/route-on-non-openshift`, `net/ingress-on-openshift`, `net/foreign-ingress-annotations`, `net/ingress-class-missing`, `net/servicelb-assumption`, `net/network-policy-default` |
| Storage | `stor/storageclass-missing`, `stor/rwx-unsupported` |
| Images | `img/imagestream-on-non-openshift`, `img/latest-tag` |
| API versions | `api/removed`, `api/deprecated`, `api/crd-missing` |
| Platform objects | `ocp/template-object`, `ocp/deploymentconfig`, `ocp/service-ca`, `k3s/traefik-crd` |
| Resources | `res/limits-missing` |

## Translate

`kubeport translate --to <target> <path>` prints a unified diff; `--write` applies it (or `--output dir/` writes copies). Only deterministic, behaviour-preserving rewrites are applied; everything else becomes a manual note. Unchanged objects are written back byte for byte.

| Rewrite | Notes |
|---|---|
| Route to Ingress | host, path, backend and port (resolved from the Service when the Route omits it), edge TLS to a `<name>-tls` Secret; passthrough, re-encrypt and redirects get controller-specific notes |
| Ingress to Route | simple Ingresses (one host, one path) on OpenShift when they carry foreign controller annotations |
| `ingressClassName` | set to the target's default class |
| StorageClass | via the target's `storage.mapping`, else the default class |
| Fixed UID | drop `runAsUser`/`runAsGroup`/`fsGroup`, keep `runAsNonRoot: true` |
| restricted hardening | `capabilities.drop: [ALL]`, `allowPrivilegeEscalation: false`, `seccompProfile: RuntimeDefault` |
| Removed APIs | `apiVersion` rewrite; `extensions/v1beta1` Ingress backends converted to the v1 shape; `apps/v1` selector added |
| OpenShift Template | expanded into plain objects, parameter defaults substituted, `${{X}}` typed |
| DeploymentConfig | to `apps/v1` Deployment; triggers and lifecycle hooks listed for follow-up |

## CI

```yaml
- uses: kubeport/kubeport/action@v1
  with:
    path: ./chart
    from: k3s:1.31
    to: openshift:4.19/vsphere,k8s:1.32/eks
    fail-on: error
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: kubeport.sarif
```

Output formats: `--format text|json|sarif|matrix|badge`. `matrix` prints a Markdown compatibility table for a README; `badge` prints shields.io endpoint JSON. Exit codes: 0 clean, 1 findings at or above `--fail-on` (default `error`), 2 usage or tool error.

## Non-goals

Not an admission controller (use Kyverno or Gatekeeper in the cluster; Kubeport is the check before you get there). Not a general best-practice linter (kube-score, Polaris). Not a cluster scanner: it never connects to a cluster and needs no credentials.

## Contributing

Rules, targets and fixtures are data. [CONTRIBUTING.md](CONTRIBUTING.md) walks through adding each in under an hour. Code of conduct: CNCF. License: Apache-2.0, DCO sign-off, no CLA.

Site: [kubeport.kosir.info](https://kubeport.kosir.info). Founding document: [docs/founding-document.md](docs/founding-document.md).
