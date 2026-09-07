# Cluster profiles

A profile describes what *your* cluster accepts. Kubeport ships generic facts for each distribution and a few well-known profiles (`kubeport targets`); a profile file lets a platform team say exactly which StorageClasses, Ingress class, CRDs and admission level exist, once, and have every pipeline check against it.

```
kubeport profile init --extends openshift:4.19 --out prod-cluster.yaml
# edit
kubeport check --to prod-cluster.yaml ./deploy
```

## Schema

Every field is optional except `extends`. Omitted fields inherit from the base target.

| Field | Type | Meaning |
|---|---|---|
| `extends` | string | Base target, e.g. `openshift:4.19`, `k8s:1.32/eks`, `k3s:1.31` |
| `profile` | string | Short name shown in reports (defaults to the file name) |
| `display` | string | Human description |
| `admission` | `scc` \| `psa` \| `none` | Pod security mechanism |
| `psa_level` | `privileged` \| `baseline` \| `restricted` | Enforced PSA level when `admission: psa` |
| `default_scc` | string | SCC granted to ordinary service accounts (OpenShift) |
| `arbitrary_uid` | bool | Target assigns UIDs; fixed `runAsUser` is an error |
| `hostpath_allowed`, `privileged_allowed` | bool | Whether hostPath volumes / privileged pods are admitted |
| `ingress.default_class` | string | Class used when an Ingress sets none |
| `ingress.controller` | string | Controller name (free text) |
| `ingress.routes` | bool | Route API available |
| `ingress.annotation_prefixes` | list | Annotation prefixes the controller understands |
| `load_balancer` | bool | `type: LoadBalancer` Services get an address |
| `storage.classes` | list | StorageClasses that exist; when set, unknown classes are errors |
| `storage.default_class` | string | Default class |
| `storage.rwx_classes` | list | Classes that support ReadWriteMany |
| `storage.mapping` | map | Foreign class to local class, used by `translate` |
| `api_groups` | list | CRD / aggregated API groups installed (see below) |
| `quotas_enforced` | bool | ResourceQuota/LimitRange present: missing requests/limits are errors |
| `network_policy_default_deny` | bool | Namespaces are isolated by default |

### Getting `api_groups` from a live cluster

```
kubectl api-resources -o name | awk -F. 'NF>1 {sub($1".", ""); print}' | sort -u
```

PowerShell:

```
kubectl api-resources -o name | ForEach-Object { if ($_ -match '^[^.]+\.(.+)$') { $matches[1] } } | Sort-Object -Unique
```

### Getting storage classes

```
kubectl get storageclass -o custom-columns=NAME:.metadata.name,PROVISIONER:.provisioner --no-headers
```

## Example: regulated OpenShift on vSphere

```yaml
extends: openshift:4.19
profile: prod
display: production, vSphere, ODF for RWX
storage:
  classes: [thin-csi, ocs-storagecluster-cephfs]
  default_class: thin-csi
  rwx_classes: [ocs-storagecluster-cephfs]
  mapping:
    local-path: thin-csi
    gp3: thin-csi
    efs-sc: ocs-storagecluster-cephfs
api_groups:
  - route.openshift.io
  - image.openshift.io
  - monitoring.coreos.com
  - external-secrets.io
  - cert-manager.io
quotas_enforced: true
network_policy_default_deny: true
```

Commit the profile next to the pipeline that uses it, and version it with the cluster.
