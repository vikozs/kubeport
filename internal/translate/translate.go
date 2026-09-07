// Package translate applies deterministic, semantics-preserving rewrites for
// findings that rules marked as fixable. Anything ambiguous is recorded as a
// manual note instead of guessed.
package translate

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/kubeport/kubeport/internal/model"
	"github.com/kubeport/kubeport/internal/rules"
	"github.com/kubeport/kubeport/internal/targets"
)

// Change is one applied rewrite.
type Change struct {
	Object      string `json:"object"`
	Source      string `json:"source"`
	Rule        string `json:"rule"`
	Description string `json:"description"`
}

// Note is something a human must finish.
type Note struct {
	Object  string `json:"object"`
	Source  string `json:"source"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

// Result of a translation run.
type Result struct {
	Changes []Change `json:"changes"`
	Notes   []Note   `json:"notes"`
	// Modified marks objects whose Data changed and must be re-serialised.
	Modified map[*model.Object]bool `json:"-"`
	// Replaced maps an original object to the objects that replace it (Template
	// expansion, Route<->Ingress, DeploymentConfig->Deployment).
	Replaced map[*model.Object][]*model.Object `json:"-"`
}

func (r *Result) change(o *model.Object, rule, desc string) {
	r.Changes = append(r.Changes, Change{Object: o.Ref(), Source: o.Source, Rule: rule, Description: desc})
	r.Modified[o] = true
}

func (r *Result) note(o *model.Object, rule, msg string) {
	r.Notes = append(r.Notes, Note{Object: o.Ref(), Source: o.Source, Rule: rule, Message: msg})
}

// Apply rewrites the bundle in place for one target and returns what it did.
func Apply(b *model.Bundle, to *targets.Target, findings []rules.Finding, only map[string]bool) *Result {
	res := &Result{Modified: map[*model.Object]bool{}, Replaced: map[*model.Object][]*model.Object{}}
	c := &rules.Context{To: to, Bundle: b}

	type key struct {
		obj  *model.Object
		rule string
	}
	done := map[key]bool{}
	for _, f := range findings {
		if !f.Fixable || f.Obj() == nil {
			continue
		}
		if len(only) > 0 && !only[f.Rule] {
			continue
		}
		k := key{f.Obj(), f.Rule}
		if done[k] {
			continue
		}
		done[k] = true
		obj := f.Obj()
		switch f.Rule {
		case "sec/run-as-root":
			fixRunAsRoot(res, obj)
		case "sec/fixed-uid":
			fixFixedUID(res, obj)
		case "sec/capabilities":
			fixCapabilities(res, obj)
		case "sec/allow-privilege-escalation":
			fixPrivEsc(res, obj)
		case "sec/seccomp-profile":
			fixSeccomp(res, obj)
		case "stor/storageclass-missing":
			fixStorageClass(res, obj, to)
		case "net/route-on-non-openshift":
			routeToIngress(res, obj, to, b)
		case "net/ingress-on-openshift":
			ingressToRoute(res, obj, c)
		case "net/foreign-ingress-annotations":
			fixIngressClass(res, obj, to)
		case "api/removed", "api/deprecated":
			fixAPIVersion(res, obj)
		case "ocp/template-object":
			expandTemplate(res, obj)
		case "ocp/deploymentconfig":
			dcToDeployment(res, obj)
		}
	}

	// Swap replaced objects into the bundle, preserving order.
	if len(res.Replaced) > 0 {
		var objs []*model.Object
		for _, o := range b.Objects {
			if repl, ok := res.Replaced[o]; ok {
				objs = append(objs, repl...)
				continue
			}
			objs = append(objs, o)
		}
		b.Objects = objs
	}
	sort.SliceStable(res.Changes, func(i, j int) bool { return res.Changes[i].Source < res.Changes[j].Source })
	return res
}

// ------------------------------------------------------------- security fixes

func podSC(ps model.PodSpec) map[string]any {
	sc, ok := ps.Spec["securityContext"].(map[string]any)
	if !ok {
		sc = map[string]any{}
		ps.Spec["securityContext"] = sc
	}
	return sc
}

func ctrSC(ct model.Container) map[string]any {
	sc, ok := ct.Spec["securityContext"].(map[string]any)
	if !ok {
		sc = map[string]any{}
		ct.Spec["securityContext"] = sc
	}
	return sc
}

func fixRunAsRoot(r *Result, o *model.Object) {
	for _, ps := range o.PodSpecs() {
		sc := podSC(ps)
		if n, ok := model.Int64(sc["runAsUser"]); ok && n == 0 {
			r.note(o, "sec/run-as-root", "pod explicitly runs as UID 0; not changed. Rebuild the image for a non-root user.")
			continue
		}
		sc["runAsNonRoot"] = true
		for _, ct := range ps.Containers() {
			csc := ct.SecurityContext()
			if csc == nil {
				continue
			}
			if b, ok := model.Bool(csc["runAsNonRoot"]); ok && !b {
				delete(csc, "runAsNonRoot")
			}
			if n, ok := model.Int64(csc["runAsUser"]); ok && n == 0 {
				r.note(o, "sec/run-as-root", fmt.Sprintf("container %q explicitly runs as UID 0; not changed", ct.Name))
			}
		}
		r.change(o, "sec/run-as-root", "set "+ps.Path+".securityContext.runAsNonRoot=true")
	}
}

func fixFixedUID(r *Result, o *model.Object) {
	for _, ps := range o.PodSpecs() {
		var removed []string
		sc := podSC(ps)
		for _, k := range []string{"runAsUser", "runAsGroup", "fsGroup"} {
			if n, ok := model.Int64(sc[k]); ok && n != 0 {
				delete(sc, k)
				removed = append(removed, "pod."+k)
			}
		}
		sc["runAsNonRoot"] = true
		for _, ct := range ps.Containers() {
			csc := ct.SecurityContext()
			if csc == nil {
				continue
			}
			for _, k := range []string{"runAsUser", "runAsGroup"} {
				if n, ok := model.Int64(csc[k]); ok && n != 0 {
					delete(csc, k)
					removed = append(removed, ct.Name+"."+k)
				}
			}
		}
		if len(removed) > 0 {
			r.change(o, "sec/fixed-uid", "removed "+strings.Join(removed, ", ")+"; kept runAsNonRoot=true (OpenShift assigns the UID). Make sure the image's writable paths are group-writable by GID 0.")
		}
	}
}

func fixCapabilities(r *Result, o *model.Object) {
	for _, ps := range o.PodSpecs() {
		var names []string
		for _, ct := range ps.Containers() {
			sc := ctrSC(ct)
			caps, ok := sc["capabilities"].(map[string]any)
			if !ok {
				caps = map[string]any{}
				sc["capabilities"] = caps
			}
			has := false
			for _, d := range asList(caps["drop"]) {
				if strings.EqualFold(model.Str(d), "ALL") {
					has = true
				}
			}
			if !has {
				caps["drop"] = []any{"ALL"}
				names = append(names, ct.Name)
			}
		}
		if len(names) > 0 {
			r.change(o, "sec/capabilities", "added capabilities.drop [ALL] to "+strings.Join(names, ", "))
		}
	}
}

func fixPrivEsc(r *Result, o *model.Object) {
	for _, ps := range o.PodSpecs() {
		var names []string
		for _, ct := range ps.Containers() {
			sc := ctrSC(ct)
			if b, ok := model.Bool(sc["allowPrivilegeEscalation"]); ok && !b {
				continue
			}
			sc["allowPrivilegeEscalation"] = false
			names = append(names, ct.Name)
		}
		if len(names) > 0 {
			r.change(o, "sec/allow-privilege-escalation", "set allowPrivilegeEscalation=false on "+strings.Join(names, ", "))
		}
	}
}

func fixSeccomp(r *Result, o *model.Object) {
	for _, ps := range o.PodSpecs() {
		sc := podSC(ps)
		if _, ok := sc["seccompProfile"]; ok {
			continue
		}
		sc["seccompProfile"] = map[string]any{"type": "RuntimeDefault"}
		r.change(o, "sec/seccomp-profile", "set "+ps.Path+".securityContext.seccompProfile.type=RuntimeDefault")
	}
}

// -------------------------------------------------------------- storage fix

func fixStorageClass(r *Result, o *model.Object, to *targets.Target) {
	apply := func(spec map[string]any, where string) {
		class := model.Str(spec["storageClassName"])
		if class == "" || to.HasStorageClass(class) && len(to.Storage.Classes) > 0 {
			return
		}
		repl := to.Storage.Mapping[class]
		if repl == "" && len(to.Storage.Classes) > 0 {
			repl = to.Storage.DefaultClass
		}
		if repl == "" {
			r.note(o, "stor/storageclass-missing", fmt.Sprintf("%s: no mapping for StorageClass %q on %s; add storage.mapping to a profile", where, class, to.ID()))
			return
		}
		spec["storageClassName"] = repl
		r.change(o, "stor/storageclass-missing", fmt.Sprintf("%s: storageClassName %s -> %s", where, class, repl))
	}
	if o.Kind() == "PersistentVolumeClaim" {
		if s, ok := o.Data["spec"].(map[string]any); ok {
			apply(s, "spec")
		}
	}
	if o.Kind() == "StatefulSet" {
		if l, ok := o.Get("spec.volumeClaimTemplates"); ok {
			for i, t := range asList(l) {
				if tm, ok := t.(map[string]any); ok {
					if s, ok := tm["spec"].(map[string]any); ok {
						apply(s, fmt.Sprintf("volumeClaimTemplates[%d]", i))
					}
				}
			}
		}
	}
}

// ------------------------------------------------------------ Route<->Ingress

func metaCopy(o *model.Object, dropPrefixes ...string) (map[string]any, []string) {
	md := map[string]any{}
	src, _ := o.Data["metadata"].(map[string]any)
	var dropped []string
	for _, k := range []string{"name", "namespace", "labels"} {
		if v, ok := src[k]; ok {
			md[k] = v
		}
	}
	if ann, ok := src["annotations"].(map[string]any); ok {
		keep := map[string]any{}
		for k, v := range ann {
			drop := false
			for _, p := range dropPrefixes {
				if strings.HasPrefix(k, p) {
					drop = true
				}
			}
			if drop {
				dropped = append(dropped, k)
			} else {
				keep[k] = v
			}
		}
		if len(keep) > 0 {
			md["annotations"] = keep
		}
	}
	sort.Strings(dropped)
	return md, dropped
}

func routeToIngress(r *Result, o *model.Object, to *targets.Target, b *model.Bundle) {
	spec, _ := o.Data["spec"].(map[string]any)
	toRef, _ := spec["to"].(map[string]any)
	svc := model.Str(toRef["name"])
	if svc == "" {
		r.note(o, "net/route-on-non-openshift", "Route has no spec.to.name; not converted")
		return
	}
	// Resolve the port.
	var port map[string]any
	if p, ok := spec["port"].(map[string]any); ok {
		if n, ok := model.Int64(p["targetPort"]); ok {
			port = map[string]any{"number": n}
		} else if s := model.Str(p["targetPort"]); s != "" {
			port = map[string]any{"name": s}
		}
	}
	if port == nil {
		// Fall back to the first port of the Service in the bundle.
		for _, s := range b.Objects {
			if s.Kind() == "Service" && s.Name() == svc {
				if ports, ok := s.Get("spec.ports"); ok {
					if l := asList(ports); len(l) > 0 {
						if pm, ok := l[0].(map[string]any); ok {
							if n, ok := model.Int64(pm["port"]); ok {
								port = map[string]any{"number": n}
							}
						}
					}
				}
			}
		}
	}
	if port == nil {
		port = map[string]any{"number": int64(80)}
		r.note(o, "net/route-on-non-openshift", fmt.Sprintf("could not determine the Service port for %s; Ingress backend set to port 80, verify", svc))
	}
	md, dropped := metaCopy(o, "haproxy.router.openshift.io/", "openshift.io/", "route.openshift.io/")
	ann, _ := md["annotations"].(map[string]any)
	if ann == nil {
		ann = map[string]any{}
	}
	path := model.Str(spec["path"])
	if path == "" {
		path = "/"
	}
	rule := map[string]any{
		"http": map[string]any{"paths": []any{map[string]any{
			"path": path, "pathType": "Prefix",
			"backend": map[string]any{"service": map[string]any{"name": svc, "port": port}},
		}}},
	}
	host := model.Str(spec["host"])
	if host != "" {
		rule["host"] = host
	} else {
		r.note(o, "net/route-on-non-openshift", "Route relied on an OpenShift-generated hostname; set a host on the Ingress")
	}
	ing := map[string]any{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "Ingress",
		"metadata":   md,
		"spec":       map[string]any{"rules": []any{rule}},
	}
	if to.Ingress.DefaultClass != "" {
		ing["spec"].(map[string]any)["ingressClassName"] = to.Ingress.DefaultClass
	}
	if tls, ok := spec["tls"].(map[string]any); ok {
		term := model.Str(tls["termination"])
		secret := o.Name() + "-tls"
		tlsEntry := map[string]any{"secretName": secret}
		if host != "" {
			tlsEntry["hosts"] = []any{host}
		}
		ing["spec"].(map[string]any)["tls"] = []any{tlsEntry}
		switch term {
		case "passthrough":
			if to.Ingress.DefaultClass == "nginx" || strings.Contains(to.Ingress.Controller, "nginx") {
				ann["nginx.ingress.kubernetes.io/ssl-passthrough"] = "true"
			} else {
				r.note(o, "net/route-on-non-openshift", "passthrough termination: the Ingress controller must be configured for TLS passthrough (Traefik needs an IngressRouteTCP); review")
			}
			delete(ing["spec"].(map[string]any), "tls")
		case "reencrypt":
			r.note(o, "net/route-on-non-openshift", "re-encrypt termination: add the controller's backend-TLS annotation (e.g. nginx.ingress.kubernetes.io/backend-protocol: HTTPS) and review destinationCACertificate")
		}
		if model.Str(tls["certificate"]) != "" || model.Str(tls["key"]) != "" {
			r.note(o, "net/route-on-non-openshift", fmt.Sprintf("Route carried an inline certificate; create a TLS Secret named %q from it (or use cert-manager)", secret))
		} else if term != "passthrough" {
			r.note(o, "net/route-on-non-openshift", fmt.Sprintf("Ingress expects a TLS Secret named %q; the Route used the router's default certificate", secret))
		}
		if model.Str(tls["insecureEdgeTerminationPolicy"]) == "Redirect" {
			if strings.Contains(to.Ingress.Controller, "nginx") {
				ann["nginx.ingress.kubernetes.io/ssl-redirect"] = "true"
			} else if to.IsK3s() || to.Ingress.DefaultClass == "traefik" {
				ann["traefik.ingress.kubernetes.io/router.entrypoints"] = "web,websecure"
				r.note(o, "net/route-on-non-openshift", "HTTP->HTTPS redirect: add a Traefik redirectScheme middleware (not expressible as a plain Ingress annotation)")
			} else {
				r.note(o, "net/route-on-non-openshift", "HTTP->HTTPS redirect must be configured on the target's Ingress controller")
			}
		}
	}
	if len(ann) > 0 {
		md["annotations"] = ann
	}
	if len(dropped) > 0 {
		r.note(o, "net/route-on-non-openshift", "dropped OpenShift router annotations: "+strings.Join(dropped, ", "))
	}
	n := &model.Object{Data: ing, Source: o.Source, Index: o.Index}
	r.Replaced[o] = []*model.Object{n}
	r.Changes = append(r.Changes, Change{Object: o.Ref(), Source: o.Source, Rule: "net/route-on-non-openshift", Description: "converted Route to networking.k8s.io/v1 Ingress " + n.Ref()})
	r.Modified[n] = true
}

func ingressToRoute(r *Result, o *model.Object, c *rules.Context) {
	rulesV, _ := o.Get("spec.rules")
	rl := asList(rulesV)
	if len(rl) != 1 {
		r.note(o, "net/ingress-on-openshift", "Ingress has several rules; not converted (one Route per host/path is needed)")
		return
	}
	rm, _ := rl[0].(map[string]any)
	http, _ := rm["http"].(map[string]any)
	paths := asList(http["paths"])
	if len(paths) > 1 {
		r.note(o, "net/ingress-on-openshift", "Ingress has several paths; not converted")
		return
	}
	var backend map[string]any
	path := ""
	if len(paths) == 1 {
		pm, _ := paths[0].(map[string]any)
		path = model.Str(pm["path"])
		backend, _ = pm["backend"].(map[string]any)
	} else if db, ok := o.Get("spec.defaultBackend"); ok {
		backend, _ = db.(map[string]any)
	}
	svcM, _ := backend["service"].(map[string]any)
	svc := model.Str(svcM["name"])
	if svc == "" { // extensions/v1beta1 shape
		svc = model.Str(backend["serviceName"])
	}
	if svc == "" {
		r.note(o, "net/ingress-on-openshift", "Ingress has no backend service; not converted")
		return
	}
	var targetPort any
	if pm, ok := svcM["port"].(map[string]any); ok {
		if n, ok := model.Int64(pm["number"]); ok {
			targetPort = n
		} else if s := model.Str(pm["name"]); s != "" {
			targetPort = s
		}
	} else if v, ok := backend["servicePort"]; ok {
		targetPort = v
	}
	md, dropped := metaCopy(o, "traefik.", "nginx.", "alb.", "kubernetes.io/ingress.", "ingress.kubernetes.io/", "networking.gke.io/", "cloud.google.com/", "kong", "konghq.com/", "projectcontour.io/", "appgw.")
	spec := map[string]any{
		"to": map[string]any{"kind": "Service", "name": svc},
	}
	if host := model.Str(rm["host"]); host != "" {
		spec["host"] = host
	}
	if path != "" && path != "/" {
		spec["path"] = path
	}
	if targetPort != nil {
		spec["port"] = map[string]any{"targetPort": targetPort}
	}
	if tls, ok := o.Get("spec.tls"); ok && len(asList(tls)) > 0 {
		spec["tls"] = map[string]any{"termination": "edge", "insecureEdgeTerminationPolicy": "Redirect"}
		tm, _ := asList(tls)[0].(map[string]any)
		if s := model.Str(tm["secretName"]); s != "" {
			r.note(o, "net/ingress-on-openshift", fmt.Sprintf("Route uses the router's default certificate; to keep the certificate from Secret %q, paste it into spec.tls.certificate/key or use cert-manager's openshift-routes integration", s))
		}
	}
	route := map[string]any{"apiVersion": "route.openshift.io/v1", "kind": "Route", "metadata": md, "spec": spec}
	n := &model.Object{Data: route, Source: o.Source, Index: o.Index}
	r.Replaced[o] = []*model.Object{n}
	r.Changes = append(r.Changes, Change{Object: o.Ref(), Source: o.Source, Rule: "net/ingress-on-openshift", Description: "converted Ingress to route.openshift.io/v1 Route " + n.Ref()})
	r.Modified[n] = true
	if len(dropped) > 0 {
		r.note(o, "net/ingress-on-openshift", "dropped controller annotations with no Route equivalent: "+strings.Join(dropped, ", ")+". Re-express rewrites/timeouts with haproxy.router.openshift.io/* annotations")
	}
}

func fixIngressClass(r *Result, o *model.Object, to *targets.Target) {
	if to.Ingress.DefaultClass == "" {
		return
	}
	spec, _ := o.Data["spec"].(map[string]any)
	if spec == nil {
		return
	}
	old := model.Str(spec["ingressClassName"])
	if old == to.Ingress.DefaultClass {
		return
	}
	spec["ingressClassName"] = to.Ingress.DefaultClass
	if ann := o.Annotations(); ann != nil {
		delete(ann, "kubernetes.io/ingress.class")
	}
	if old == "" {
		old = "(unset)"
	}
	r.change(o, "net/foreign-ingress-annotations", fmt.Sprintf("spec.ingressClassName %s -> %s; controller-specific annotations left in place (ignored by the target)", old, to.Ingress.DefaultClass))
}

// --------------------------------------------------------------- API versions

var apiReplacement = map[string]string{
	"extensions/v1beta1 Ingress":                                          "networking.k8s.io/v1",
	"networking.k8s.io/v1beta1 Ingress":                                   "networking.k8s.io/v1",
	"networking.k8s.io/v1beta1 IngressClass":                              "networking.k8s.io/v1",
	"extensions/v1beta1 Deployment":                                       "apps/v1",
	"extensions/v1beta1 DaemonSet":                                        "apps/v1",
	"extensions/v1beta1 ReplicaSet":                                       "apps/v1",
	"extensions/v1beta1 NetworkPolicy":                                    "networking.k8s.io/v1",
	"apps/v1beta1 Deployment":                                             "apps/v1",
	"apps/v1beta2 Deployment":                                             "apps/v1",
	"apps/v1beta1 StatefulSet":                                            "apps/v1",
	"apps/v1beta2 StatefulSet":                                            "apps/v1",
	"apps/v1beta2 DaemonSet":                                              "apps/v1",
	"rbac.authorization.k8s.io/v1beta1 ClusterRole":                       "rbac.authorization.k8s.io/v1",
	"rbac.authorization.k8s.io/v1beta1 ClusterRoleBinding":                "rbac.authorization.k8s.io/v1",
	"rbac.authorization.k8s.io/v1beta1 Role":                              "rbac.authorization.k8s.io/v1",
	"rbac.authorization.k8s.io/v1beta1 RoleBinding":                       "rbac.authorization.k8s.io/v1",
	"batch/v1beta1 CronJob":                                               "batch/v1",
	"policy/v1beta1 PodDisruptionBudget":                                  "policy/v1",
	"autoscaling/v2beta1 HorizontalPodAutoscaler":                         "autoscaling/v2",
	"autoscaling/v2beta2 HorizontalPodAutoscaler":                         "autoscaling/v2",
	"discovery.k8s.io/v1beta1 EndpointSlice":                              "discovery.k8s.io/v1",
	"events.k8s.io/v1beta1 Event":                                         "events.k8s.io/v1",
	"node.k8s.io/v1beta1 RuntimeClass":                                    "node.k8s.io/v1",
	"scheduling.k8s.io/v1beta1 PriorityClass":                             "scheduling.k8s.io/v1",
	"coordination.k8s.io/v1beta1 Lease":                                   "coordination.k8s.io/v1",
	"storage.k8s.io/v1beta1 StorageClass":                                 "storage.k8s.io/v1",
	"storage.k8s.io/v1beta1 CSIDriver":                                    "storage.k8s.io/v1",
	"storage.k8s.io/v1beta1 CSINode":                                      "storage.k8s.io/v1",
	"storage.k8s.io/v1beta1 VolumeAttachment":                             "storage.k8s.io/v1",
	"storage.k8s.io/v1beta1 CSIStorageCapacity":                           "storage.k8s.io/v1",
	"admissionregistration.k8s.io/v1beta1 MutatingWebhookConfiguration":   "admissionregistration.k8s.io/v1",
	"admissionregistration.k8s.io/v1beta1 ValidatingWebhookConfiguration": "admissionregistration.k8s.io/v1",
	"apiextensions.k8s.io/v1beta1 CustomResourceDefinition":               "apiextensions.k8s.io/v1",
	"certificates.k8s.io/v1beta1 CertificateSigningRequest":               "certificates.k8s.io/v1",
	"flowcontrol.apiserver.k8s.io/v1beta1 FlowSchema":                     "flowcontrol.apiserver.k8s.io/v1",
	"flowcontrol.apiserver.k8s.io/v1beta2 FlowSchema":                     "flowcontrol.apiserver.k8s.io/v1",
	"flowcontrol.apiserver.k8s.io/v1beta3 FlowSchema":                     "flowcontrol.apiserver.k8s.io/v1",
	"flowcontrol.apiserver.k8s.io/v1beta1 PriorityLevelConfiguration":     "flowcontrol.apiserver.k8s.io/v1",
	"flowcontrol.apiserver.k8s.io/v1beta2 PriorityLevelConfiguration":     "flowcontrol.apiserver.k8s.io/v1",
	"flowcontrol.apiserver.k8s.io/v1beta3 PriorityLevelConfiguration":     "flowcontrol.apiserver.k8s.io/v1",
}

func fixAPIVersion(r *Result, o *model.Object) {
	key := o.APIVersion() + " " + o.Kind()
	repl, ok := apiReplacement[key]
	if !ok {
		r.note(o, "api/removed", "no automatic rewrite for "+key+"; see the deprecation guide")
		return
	}
	old := o.APIVersion()
	o.Data["apiVersion"] = repl
	desc := fmt.Sprintf("apiVersion %s -> %s", old, repl)
	switch o.Kind() {
	case "Ingress":
		desc += convertIngressBackends(r, o)
	case "Deployment", "DaemonSet", "ReplicaSet", "StatefulSet":
		if _, ok := o.Get("spec.selector"); !ok {
			if labels, ok := o.Get("spec.template.metadata.labels"); ok {
				model.Set(o.Data, "spec.selector", map[string]any{"matchLabels": labels})
				desc += "; added required spec.selector from template labels"
			} else {
				r.note(o, "api/removed", "apps/v1 requires spec.selector; the template has no labels to derive it from")
			}
		}
	case "HorizontalPodAutoscaler":
		if old == "autoscaling/v2beta1" {
			r.note(o, "api/removed", "autoscaling/v2beta1 metrics use targetAverageUtilization/targetAverageValue; v2 uses target.type and target.averageUtilization/averageValue. Review spec.metrics")
		}
	case "CustomResourceDefinition":
		r.note(o, "api/removed", "apiextensions v1 requires a structural schema per version and moves validation/subresources under spec.versions[]; review")
	case "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration":
		r.note(o, "api/removed", "admissionregistration v1 requires webhooks[].admissionReviewVersions and sideEffects; review")
	}
	r.change(o, "api/removed", desc)
}

// convertIngressBackends rewrites v1beta1 backend {serviceName, servicePort}
// into v1 backend {service: {name, port}} and adds pathType.
func convertIngressBackends(r *Result, o *model.Object) string {
	conv := func(b map[string]any) {
		if b == nil || b["service"] != nil {
			return
		}
		name := model.Str(b["serviceName"])
		port := map[string]any{}
		if n, ok := model.Int64(b["servicePort"]); ok {
			port["number"] = n
		} else if s := model.Str(b["servicePort"]); s != "" {
			port["name"] = s
		}
		delete(b, "serviceName")
		delete(b, "servicePort")
		b["service"] = map[string]any{"name": name, "port": port}
	}
	n := 0
	if rl, ok := o.Get("spec.rules"); ok {
		for _, rv := range asList(rl) {
			rm, _ := rv.(map[string]any)
			http, _ := rm["http"].(map[string]any)
			for _, pv := range asList(http["paths"]) {
				pm, _ := pv.(map[string]any)
				if pm == nil {
					continue
				}
				if pm["pathType"] == nil {
					pm["pathType"] = "ImplementationSpecific"
				}
				if b, ok := pm["backend"].(map[string]any); ok {
					conv(b)
					n++
				}
			}
		}
	}
	if b, ok := o.Data["spec"].(map[string]any)["backend"].(map[string]any); ok {
		conv(b)
		o.Data["spec"].(map[string]any)["defaultBackend"] = b
		delete(o.Data["spec"].(map[string]any), "backend")
		n++
	}
	if ann := o.Annotations(); ann != nil {
		if cls, ok := ann["kubernetes.io/ingress.class"]; ok {
			if _, has := o.Get("spec.ingressClassName"); !has {
				model.Set(o.Data, "spec.ingressClassName", cls)
			}
			delete(ann, "kubernetes.io/ingress.class")
		}
	}
	return fmt.Sprintf("; converted %d backend(s) to v1 shape and set pathType ImplementationSpecific", n)
}

// ------------------------------------------------------------- Template

var paramRe = regexp.MustCompile(`\$\{\{?([A-Za-z_][A-Za-z0-9_]*)\}?\}`)

func expandTemplate(r *Result, o *model.Object) {
	params := map[string]string{}
	var unresolved []string
	for _, pv := range asList(o.Data["parameters"]) {
		pm, _ := pv.(map[string]any)
		name := model.Str(pm["name"])
		if v, ok := pm["value"]; ok {
			params[name] = model.Str(v)
		} else if model.Str(pm["generate"]) != "" {
			unresolved = append(unresolved, name+" (generated)")
		} else {
			unresolved = append(unresolved, name)
		}
	}
	var out []*model.Object
	for i, ov := range asList(o.Data["objects"]) {
		om, ok := ov.(map[string]any)
		if !ok {
			continue
		}
		substituted := substitute(om, params).(map[string]any)
		out = append(out, &model.Object{Data: substituted, Source: o.Source, Index: o.Index*1000 + i})
	}
	for _, n := range out {
		r.Modified[n] = true
	}
	r.Replaced[o] = out
	r.Changes = append(r.Changes, Change{Object: o.Ref(), Source: o.Source, Rule: "ocp/template-object",
		Description: fmt.Sprintf("expanded Template into %d object(s), substituting %d parameter default(s)", len(out), len(params))})
	if len(unresolved) > 0 {
		sort.Strings(unresolved)
		r.note(o, "ocp/template-object", "parameters without a default were left as ${NAME} placeholders: "+strings.Join(unresolved, ", ")+". Provide values (a Helm values file or envsubst) before applying")
	}
}

var wholeTypedRe = regexp.MustCompile(`^\$\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}$`)

func substitute(v any, params map[string]string) any {
	switch t := v.(type) {
	case string:
		// ${{NAME}} on its own means "substitute as a typed value".
		if m := wholeTypedRe.FindStringSubmatch(t); m != nil {
			if val, ok := params[m[1]]; ok {
				return typed(val)
			}
			return t
		}
		return paramRe.ReplaceAllStringFunc(t, func(m string) string {
			name := paramRe.FindStringSubmatch(m)[1]
			if val, ok := params[name]; ok {
				return val
			}
			return m
		})
	case map[string]any:
		for k, vv := range t {
			t[k] = substitute(vv, params)
		}
		return t
	case []any:
		for i := range t {
			t[i] = substitute(t[i], params)
		}
		return t
	}
	return v
}

// ------------------------------------------------------ DeploymentConfig

func dcToDeployment(r *Result, o *model.Object) {
	spec, _ := o.Data["spec"].(map[string]any)
	md, _ := metaCopy(o, "openshift.io/", "image.openshift.io/")
	newSpec := map[string]any{}
	if v, ok := spec["replicas"]; ok {
		newSpec["replicas"] = v
	}
	if sel, ok := spec["selector"].(map[string]any); ok {
		if sel["matchLabels"] != nil || sel["matchExpressions"] != nil {
			newSpec["selector"] = sel
		} else {
			newSpec["selector"] = map[string]any{"matchLabels": sel}
		}
	} else if labels, ok := model.Get(spec, "template.metadata.labels"); ok {
		newSpec["selector"] = map[string]any{"matchLabels": labels}
	}
	if t, ok := spec["template"]; ok {
		newSpec["template"] = t
	}
	if v, ok := spec["minReadySeconds"]; ok {
		newSpec["minReadySeconds"] = v
	}
	if v, ok := spec["revisionHistoryLimit"]; ok {
		newSpec["revisionHistoryLimit"] = v
	}
	if v, ok := spec["paused"]; ok {
		newSpec["paused"] = v
	}
	if st, ok := spec["strategy"].(map[string]any); ok {
		typ := model.Str(st["type"])
		switch typ {
		case "Rolling", "":
			s := map[string]any{"type": "RollingUpdate"}
			if rp, ok := st["rollingParams"].(map[string]any); ok {
				ru := map[string]any{}
				if v, ok := rp["maxSurge"]; ok {
					ru["maxSurge"] = v
				}
				if v, ok := rp["maxUnavailable"]; ok {
					ru["maxUnavailable"] = v
				}
				if len(ru) > 0 {
					s["rollingUpdate"] = ru
				}
				if rp["pre"] != nil || rp["post"] != nil || rp["mid"] != nil {
					r.note(o, "ocp/deploymentconfig", "lifecycle hooks (rollingParams.pre/mid/post) have no Deployment equivalent; use init containers, Jobs or Argo Rollouts hooks")
				}
			}
			newSpec["strategy"] = s
		case "Recreate":
			newSpec["strategy"] = map[string]any{"type": "Recreate"}
			if rp, ok := st["recreateParams"].(map[string]any); ok && (rp["pre"] != nil || rp["post"] != nil || rp["mid"] != nil) {
				r.note(o, "ocp/deploymentconfig", "lifecycle hooks (recreateParams.pre/mid/post) have no Deployment equivalent")
			}
		case "Custom":
			r.note(o, "ocp/deploymentconfig", "Custom deployment strategy dropped; Deployment supports RollingUpdate and Recreate only")
		}
	}
	// Triggers.
	for _, tv := range asList(spec["triggers"]) {
		tm, _ := tv.(map[string]any)
		if model.Str(tm["type"]) == "ImageChange" {
			icp, _ := tm["imageChangeParams"].(map[string]any)
			from, _ := icp["from"].(map[string]any)
			r.note(o, "ocp/deploymentconfig", fmt.Sprintf("ImageChange trigger from %s %q dropped; set the container image to a fully qualified reference and drive rollouts from CI/GitOps", model.Str(from["kind"]), model.Str(from["name"])))
		}
	}
	// Empty images (filled in by ImageChange triggers) must be fixed by hand.
	dep := map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": md, "spec": newSpec}
	n := &model.Object{Data: dep, Source: o.Source, Index: o.Index}
	for _, ps := range n.PodSpecs() {
		for _, ct := range ps.Containers() {
			if strings.TrimSpace(model.Str(ct.Spec["image"])) == "" {
				r.note(o, "ocp/deploymentconfig", fmt.Sprintf("container %q has an empty image (was resolved by an ImageChange trigger); set it explicitly", ct.Name))
			}
		}
	}
	r.Replaced[o] = []*model.Object{n}
	r.Modified[n] = true
	r.Changes = append(r.Changes, Change{Object: o.Ref(), Source: o.Source, Rule: "ocp/deploymentconfig", Description: "converted DeploymentConfig to apps/v1 Deployment"})
}

// typed converts a template parameter string into int, bool or float when it
// parses as one, mirroring `oc process` behaviour for ${{PARAM}}.
func typed(s string) any {
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n
	}
	if b, err := strconv.ParseBool(s); err == nil {
		return b
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}
	return s
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}
