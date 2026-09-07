package rules

import (
	"fmt"
	"strings"

	"github.com/kubeport/kubeport/internal/catalog"
	"github.com/kubeport/kubeport/internal/model"
)

func init() {
	register(routeOnNonOpenShift{})
	register(ingressAnnotations{})
	register(ingressClassMissing{})
	register(serviceLB{})
	register(networkPolicyDefault{})
	register(storageClassMissing{})
	register(rwxUnsupported{})
	register(imageStream{})
	register(latestTag{})
	register(apiRemoved{})
	register(crdMissing{})
	register(templateObject{})
	register(deploymentConfig{})
	register(serviceCA{})
	register(traefikCRD{})
	register(limitsMissing{})
}

// ------------------------------------------------------------------- Routes
type routeOnNonOpenShift struct{}

func (routeOnNonOpenShift) ID() string { return "net/route-on-non-openshift" }
func (r routeOnNonOpenShift) Check(c *Context, obj *model.Object) []Finding {
	if obj.Group() != "route.openshift.io" || c.To.Ingress.Routes {
		return nil
	}
	fixable := obj.Kind() == "Route"
	term := ""
	if t, ok := obj.Get("spec.tls.termination"); ok {
		term = model.Str(t)
	}
	msg := fmt.Sprintf("%s has no Route API; convert to a networking.k8s.io/v1 Ingress", c.To.Display)
	if term == "reencrypt" {
		msg += " (re-encrypt termination needs controller-specific backend TLS annotations; review after conversion)"
	}
	return []Finding{c.finding(r.ID(), Error, obj, "", msg, fixable)}
}

// ------------------------------------------------------ Ingress annotations
// controllerOf maps annotation prefixes and class names to a controller family.
var controllerPrefixes = map[string]string{
	"traefik.ingress.kubernetes.io/": "traefik",
	"traefik.io/":                    "traefik",
	"nginx.ingress.kubernetes.io/":   "nginx",
	"nginx.org/":                     "nginx",
	"alb.ingress.kubernetes.io/":     "alb",
	"haproxy.router.openshift.io/":   "openshift",
	"route.openshift.io/":            "openshift",
	"haproxy-ingress.github.io/":     "haproxy",
	"ingress.kubernetes.io/":         "generic",
	"kubernetes.io/ingress.":         "gce",
	"networking.gke.io/":             "gce",
	"cloud.google.com/":              "gce",
	"appgw.ingress.kubernetes.io/":   "appgw",
	"kong/":                          "kong",
	"konghq.com/":                    "kong",
	"projectcontour.io/":             "contour",
}

var classFamilies = map[string]string{
	"traefik": "traefik", "nginx": "nginx", "alb": "alb", "openshift-default": "openshift",
	"gce": "gce", "gce-internal": "gce", "webapprouting.kubernetes.azure.com": "nginx",
	"kong": "kong", "contour": "contour", "haproxy": "haproxy",
}

func annotationFamily(key string) string {
	if key == "kubernetes.io/ingress.class" || key == "kubernetes.io/ingress.allow-http" {
		return "" // generic, handled separately
	}
	for p, fam := range controllerPrefixes {
		if strings.HasPrefix(key, p) {
			return fam
		}
	}
	return ""
}

func targetFamily(c *Context) string {
	if c.To.IsOpenShift() {
		return "openshift"
	}
	if f, ok := classFamilies[c.To.Ingress.DefaultClass]; ok {
		return f
	}
	if c.To.Ingress.Controller != "" {
		return strings.Fields(c.To.Ingress.Controller)[0]
	}
	return ""
}

func targetAccepts(c *Context, key string) bool {
	for _, p := range c.To.Ingress.AnnotationPrefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

type ingressAnnotations struct{}

func (ingressAnnotations) ID() string { return "net/ingress-on-openshift" }
func (r ingressAnnotations) Check(c *Context, obj *model.Object) []Finding {
	if obj.Kind() != "Ingress" || obj.Group() != "networking.k8s.io" && obj.Group() != "extensions" {
		return nil
	}
	rule := "net/foreign-ingress-annotations"
	if c.To.IsOpenShift() {
		rule = r.ID()
	}
	tf := targetFamily(c)
	var out []Finding
	var foreign []string
	for k := range obj.Annotations() {
		fam := annotationFamily(k)
		if fam == "" || fam == "generic" || fam == tf || targetAccepts(c, k) {
			continue
		}
		foreign = append(foreign, k)
	}
	if len(foreign) > 0 {
		sev := Warn
		simple := isSimpleIngress(obj)
		msg := fmt.Sprintf("%d annotation(s) for another Ingress controller are ignored by %s: %s", len(foreign), c.To.Display, strings.Join(sortedTrunc(foreign, 3), ", "))
		if c.To.IsOpenShift() {
			msg += ". The OpenShift Router serves the Ingress but drops these; behaviour such as rewrites, middlewares or rate limits is lost"
		}
		out = append(out, c.finding(rule, sev, obj, "metadata.annotations", msg, c.To.IsOpenShift() && simple || !c.To.IsOpenShift() && c.To.Ingress.DefaultClass != ""))
	}
	// ingressClassName pointing at a controller family the target does not run.
	class := ""
	if v, ok := obj.Get("spec.ingressClassName"); ok {
		class = model.Str(v)
	} else if a := obj.Annotations(); a != nil {
		class = model.Str(a["kubernetes.io/ingress.class"])
	}
	if class != "" && tf != "" {
		if fam, known := classFamilies[class]; known && fam != tf && class != c.To.Ingress.DefaultClass {
			out = append(out, c.finding(rule, Warn, obj, "spec.ingressClassName",
				fmt.Sprintf("ingressClassName %q targets a %s controller; %s default class is %q", class, fam, c.To.Display, c.To.Ingress.DefaultClass), c.To.Ingress.DefaultClass != ""))
		}
	}
	return out
}

func sortedTrunc(s []string, n int) []string {
	if len(s) > n {
		return append(s[:n], fmt.Sprintf("(+%d more)", len(s)-n))
	}
	return s
}

// isSimpleIngress: one rule, one host, at most one path, one backend.
func isSimpleIngress(obj *model.Object) bool {
	rules, ok := obj.Get("spec.rules")
	if !ok {
		return false
	}
	rl, ok := rules.([]any)
	if !ok || len(rl) != 1 {
		return false
	}
	rm, _ := rl[0].(map[string]any)
	http, _ := rm["http"].(map[string]any)
	paths, _ := http["paths"].([]any)
	return len(paths) <= 1
}

// ------------------------------------------------------ ingress class missing
type ingressClassMissing struct{}

func (ingressClassMissing) ID() string { return "net/ingress-class-missing" }
func (r ingressClassMissing) Check(c *Context, obj *model.Object) []Finding {
	if obj.Kind() != "Ingress" || c.To.Ingress.DefaultClass != "" {
		return nil
	}
	if _, ok := obj.Get("spec.ingressClassName"); ok {
		return nil
	}
	if a := obj.Annotations(); a != nil && a["kubernetes.io/ingress.class"] != nil {
		return nil
	}
	return []Finding{c.finding(r.ID(), Error, obj, "spec.ingressClassName",
		fmt.Sprintf("no ingressClassName and %s has no default Ingress controller; the Ingress will never get an address", c.To.Display), false)}
}

// ------------------------------------------------------------- LoadBalancer
type serviceLB struct{}

func (serviceLB) ID() string { return "net/servicelb-assumption" }
func (r serviceLB) Check(c *Context, obj *model.Object) []Finding {
	if obj.Kind() != "Service" || c.To.LoadBalancer {
		return nil
	}
	if t, _ := obj.Get("spec.type"); model.Str(t) != "LoadBalancer" {
		return nil
	}
	msg := fmt.Sprintf("Service type LoadBalancer stays <pending> on %s (no LoadBalancer implementation)", c.To.Display)
	if c.From != nil && c.From.IsK3s() {
		msg += "; on k3s ServiceLB (Klipper) made this work by binding node IPs"
	}
	return []Finding{c.finding(r.ID(), Error, obj, "spec.type", msg+". Use NodePort, an Ingress, or install MetalLB", false)}
}

// ------------------------------------------------------- NetworkPolicy check
type networkPolicyDefault struct{}

func (networkPolicyDefault) ID() string { return "net/network-policy-default" }
func (r networkPolicyDefault) CheckBundle(c *Context) []Finding {
	if !c.To.NetworkPolicyDefaultDeny {
		return nil
	}
	hasService, hasNP := false, false
	for _, o := range c.Bundle.Objects {
		switch o.Kind() {
		case "Service":
			hasService = true
		case "NetworkPolicy":
			hasNP = true
		}
	}
	if hasService && !hasNP {
		return []Finding{c.finding(r.ID(), Warn, nil, "",
			fmt.Sprintf("%s isolates the namespace by default and this bundle defines Services but no NetworkPolicy admitting traffic to them", c.To.Display), false)}
	}
	return nil
}

// ------------------------------------------------------------ StorageClass
// foreignClasses maps well-known class names to the distribution/profile that ships them.
var foreignClasses = map[string]string{
	"local-path": "k3s", "gp2": "eks", "gp3": "eks", "efs-sc": "eks", "gp2-csi": "rosa", "gp3-csi": "rosa",
	"standard-rwo": "gke", "premium-rwo": "gke", "standard-rwx": "gke",
	"managed-csi": "aks", "managed-csi-premium": "aks", "managed-premium": "aks", "azurefile-csi": "aks", "azurefile-csi-premium": "aks",
	"thin-csi": "openshift/vsphere", "thin": "openshift/vsphere",
	"ocs-storagecluster-ceph-rbd": "openshift/odf", "ocs-storagecluster-cephfs": "openshift/odf",
	"longhorn": "longhorn", "nfs-client": "nfs-subdir-external-provisioner", "hostpath": "minikube", "microk8s-hostpath": "microk8s",
}

// noRWX are classes known to be single-node block storage.
var noRWX = map[string]bool{
	"local-path": true, "gp2": true, "gp3": true, "gp2-csi": true, "gp3-csi": true, "thin-csi": true, "thin": true,
	"managed-csi": true, "managed-csi-premium": true, "managed-premium": true, "standard-rwo": true, "premium-rwo": true,
	"ocs-storagecluster-ceph-rbd": true, "hostpath": true, "microk8s-hostpath": true,
}

// claims returns every PVC spec in an object: PersistentVolumeClaim objects and
// StatefulSet volumeClaimTemplates.
func claims(obj *model.Object) []struct {
	Spec map[string]any
	Path string
	Name string
} {
	type claim = struct {
		Spec map[string]any
		Path string
		Name string
	}
	var out []claim
	if obj.Kind() == "PersistentVolumeClaim" {
		if s, ok := obj.Data["spec"].(map[string]any); ok {
			out = append(out, claim{s, "spec", obj.Name()})
		}
	}
	if obj.Kind() == "StatefulSet" {
		if list, ok := obj.Get("spec.volumeClaimTemplates"); ok {
			if l, ok := list.([]any); ok {
				for i, t := range l {
					tm, _ := t.(map[string]any)
					s, _ := tm["spec"].(map[string]any)
					name := ""
					if md, ok := tm["metadata"].(map[string]any); ok {
						name = model.Str(md["name"])
					}
					if s != nil {
						out = append(out, claim{s, fmt.Sprintf("spec.volumeClaimTemplates[%d].spec", i), name})
					}
				}
			}
		}
	}
	return out
}

type storageClassMissing struct{}

func (storageClassMissing) ID() string { return "stor/storageclass-missing" }
func (r storageClassMissing) Check(c *Context, obj *model.Object) []Finding {
	var out []Finding
	for _, cl := range claims(obj) {
		class := model.Str(cl.Spec["storageClassName"])
		if class == "" {
			if len(c.To.Storage.Classes) > 0 && c.To.Storage.DefaultClass == "" {
				out = append(out, c.finding(r.ID(), Warn, obj, cl.Path+".storageClassName",
					fmt.Sprintf("claim %q has no storageClassName and %s has no default StorageClass; the PVC will stay Pending", cl.Name, c.To.Display), false))
			}
			continue
		}
		if len(c.To.Storage.Classes) > 0 {
			if c.To.HasStorageClass(class) {
				continue
			}
			repl := c.To.Storage.Mapping[class]
			if repl == "" {
				repl = c.To.Storage.DefaultClass
			}
			msg := fmt.Sprintf("claim %q uses StorageClass %q which %s does not have", cl.Name, class, c.To.Display)
			if repl != "" {
				msg += fmt.Sprintf("; suggested: %s", repl)
			}
			out = append(out, c.finding(r.ID(), Error, obj, cl.Path+".storageClassName", msg, repl != ""))
			continue
		}
		// Target does not enumerate classes: flag only classes that clearly belong elsewhere.
		if owner, ok := foreignClasses[class]; ok && !strings.HasPrefix(owner, c.To.Name) && owner != c.To.Name+"/"+c.To.Profile {
			out = append(out, c.finding(r.ID(), Warn, obj, cl.Path+".storageClassName",
				fmt.Sprintf("claim %q uses StorageClass %q, which is specific to %s; %s ships something else (set storage.classes in a profile to get an exact answer)", cl.Name, class, owner, c.To.Display), c.To.Storage.Mapping[class] != ""))
		}
	}
	return out
}

type rwxUnsupported struct{}

func (rwxUnsupported) ID() string { return "stor/rwx-unsupported" }
func (r rwxUnsupported) Check(c *Context, obj *model.Object) []Finding {
	var out []Finding
	for _, cl := range claims(obj) {
		rwx := false
		for _, m := range toStrings(cl.Spec["accessModes"]) {
			if m == "ReadWriteMany" {
				rwx = true
			}
		}
		if !rwx {
			continue
		}
		class := model.Str(cl.Spec["storageClassName"])
		effective := class
		if effective == "" {
			effective = c.To.Storage.DefaultClass
		}
		known := len(c.To.Storage.Classes) > 0 && (effective != "" && c.To.HasStorageClass(effective))
		if known && !c.To.SupportsRWX(effective) || noRWX[effective] {
			hint := ""
			if len(c.To.Storage.RWXClasses) > 0 {
				hint = "; RWX-capable on this target: " + strings.Join(c.To.Storage.RWXClasses, ", ")
			}
			out = append(out, c.finding(r.ID(), Error, obj, cl.Path+".accessModes",
				fmt.Sprintf("claim %q asks for ReadWriteMany on StorageClass %q, which only provides single-node volumes%s", cl.Name, effective, hint), false))
		}
	}
	return out
}

// ------------------------------------------------------------------ images
type imageStream struct{}

func (imageStream) ID() string { return "img/imagestream-on-non-openshift" }
func (r imageStream) Check(c *Context, obj *model.Object) []Finding {
	if c.To.IsOpenShift() {
		return nil
	}
	var out []Finding
	if obj.Group() == "image.openshift.io" {
		out = append(out, c.finding(r.ID(), Error, obj, "", fmt.Sprintf("%s is an OpenShift image object; %s has no ImageStream API", obj.Kind(), c.To.Display), false))
	}
	for _, ps := range obj.PodSpecs() {
		for _, ct := range ps.Containers() {
			img := model.Str(ct.Spec["image"])
			if strings.Contains(img, "image-registry.openshift-image-registry.svc") || strings.Contains(img, ".apps.") && strings.Contains(img, "default-route-openshift-image-registry") {
				out = append(out, c.finding(r.ID(), Error, obj, ct.Path+".image",
					fmt.Sprintf("container %q pulls from the OpenShift internal registry (%s); push the image to a registry the target can reach", ct.Name, img), false))
			}
		}
	}
	return out
}

type latestTag struct{}

func (latestTag) ID() string { return "img/latest-tag" }
func (r latestTag) Check(c *Context, obj *model.Object) []Finding {
	var out []Finding
	for _, ps := range obj.PodSpecs() {
		for _, ct := range ps.Containers() {
			img := model.Str(ct.Spec["image"])
			if img == "" || strings.Contains(img, "@sha256:") {
				continue
			}
			// tag is after the last colon that follows the last slash
			last := img
			if i := strings.LastIndex(img, "/"); i >= 0 {
				last = img[i+1:]
			}
			tag := ""
			if i := strings.LastIndex(last, ":"); i >= 0 {
				tag = last[i+1:]
			}
			if tag == "" || tag == "latest" {
				out = append(out, c.finding(r.ID(), Info, obj, ct.Path+".image",
					fmt.Sprintf("container %q image %q has no pinned tag; different clusters will pull different images", ct.Name, img), false))
			}
		}
	}
	return out
}

// -------------------------------------------------------------------- APIs
type apiRemoved struct{}

func (apiRemoved) ID() string { return "api/removed" }
func (r apiRemoved) Check(c *Context, obj *model.Object) []Finding {
	minor := c.To.KubeMinor()
	for _, a := range catalog.APIs() {
		if a.APIVersion != obj.APIVersion() || a.Kind != obj.Kind() {
			continue
		}
		if strings.HasSuffix(obj.Group(), "openshift.io") && !c.To.IsOpenShift() {
			return nil // handled by ocp/* rules
		}
		if a.RemovedIn > 0 && minor >= a.RemovedIn {
			fixable := !strings.Contains(a.Replacement, " ")
			return []Finding{c.finding(r.ID(), Error, obj, "apiVersion",
				fmt.Sprintf("%s %s was removed in Kubernetes 1.%d (%s runs 1.%d); use %s", obj.APIVersion(), obj.Kind(), a.RemovedIn, c.To.Display, minor, a.Replacement), fixable)}
		}
		if minor >= a.DeprecatedIn {
			when := "removal not yet scheduled"
			if a.RemovedIn > 0 {
				when = fmt.Sprintf("removed in 1.%d", a.RemovedIn)
			}
			return []Finding{c.finding("api/deprecated", Warn, obj, "apiVersion",
				fmt.Sprintf("%s %s is deprecated since Kubernetes 1.%d (%s); use %s", obj.APIVersion(), obj.Kind(), a.DeprecatedIn, when, a.Replacement), !strings.Contains(a.Replacement, " "))}
		}
	}
	return nil
}

var groupsHandledElsewhere = map[string]bool{
	"route.openshift.io": true, "image.openshift.io": true, "template.openshift.io": true,
	"apps.openshift.io": true, "security.openshift.io": true, "traefik.io": true, "traefik.containo.us": true,
}

type crdMissing struct{}

func (crdMissing) ID() string { return "api/crd-missing" }
func (r crdMissing) Check(c *Context, obj *model.Object) []Finding {
	g := obj.Group()
	if IsBuiltinGroup(g) || groupsHandledElsewhere[g] || c.To.HasAPIGroup(g) {
		return nil
	}
	if obj.Kind() == "CustomResourceDefinition" {
		return nil
	}
	// If the bundle itself installs the CRD, it is fine.
	for _, o := range c.Bundle.Objects {
		if o.Kind() == "CustomResourceDefinition" {
			if grp, ok := o.Get("spec.group"); ok && model.Str(grp) == g {
				return nil
			}
		}
	}
	sev := Error
	msg := fmt.Sprintf("%s (%s) belongs to an API group %s is not known to have; install the operator/CRDs first", obj.Kind(), obj.APIVersion(), c.To.Display)
	if len(c.To.APIGroups) <= 1 {
		sev = Warn
		msg += " (the target lists no add-ons; declare api_groups in a profile to make this exact)"
	}
	return []Finding{c.finding(r.ID(), sev, obj, "apiVersion", msg, false)}
}

// --------------------------------------------------------------- OpenShift
type templateObject struct{}

func (templateObject) ID() string { return "ocp/template-object" }
func (r templateObject) Check(c *Context, obj *model.Object) []Finding {
	if obj.Group() != "template.openshift.io" || c.To.IsOpenShift() {
		return nil
	}
	n := 0
	if items, ok := obj.Get("objects"); ok {
		if l, ok := items.([]any); ok {
			n = len(l)
		}
	}
	return []Finding{c.finding(r.ID(), Error, obj, "", fmt.Sprintf("OpenShift Template with %d object(s) cannot be processed on %s; expand it into plain manifests", n, c.To.Display), obj.Kind() == "Template")}
}

type deploymentConfig struct{}

func (deploymentConfig) ID() string { return "ocp/deploymentconfig" }
func (r deploymentConfig) Check(c *Context, obj *model.Object) []Finding {
	if obj.Kind() != "DeploymentConfig" || c.To.IsOpenShift() {
		return nil
	}
	return []Finding{c.finding(r.ID(), Error, obj, "", fmt.Sprintf("DeploymentConfig does not exist on %s; convert to apps/v1 Deployment", c.To.Display), true)}
}

type serviceCA struct{}

func (serviceCA) ID() string { return "ocp/service-ca" }
func (r serviceCA) Check(c *Context, obj *model.Object) []Finding {
	if c.To.IsOpenShift() {
		return nil
	}
	var out []Finding
	for k := range obj.Annotations() {
		if strings.HasPrefix(k, "service.beta.openshift.io/") || strings.HasPrefix(k, "service.alpha.openshift.io/") {
			out = append(out, c.finding(r.ID(), Warn, obj, "metadata.annotations."+k,
				fmt.Sprintf("annotation %s relies on the OpenShift service-ca operator; %s needs cert-manager or a pre-created TLS Secret", k, c.To.Display), false))
		}
	}
	return out
}

// ---------------------------------------------------------------- Traefik
type traefikCRD struct{}

func (traefikCRD) ID() string { return "k3s/traefik-crd" }
func (r traefikCRD) Check(c *Context, obj *model.Object) []Finding {
	g := obj.Group()
	if (g != "traefik.io" && g != "traefik.containo.us") || c.To.HasAPIGroup(g) {
		return nil
	}
	return []Finding{c.finding(r.ID(), Error, obj, "apiVersion",
		fmt.Sprintf("%s is a Traefik custom resource; %s does not run Traefik. Use an Ingress (or Route on OpenShift) or install Traefik on the target", obj.Kind(), c.To.Display), false)}
}

// -------------------------------------------------------------- resources
type limitsMissing struct{}

func (limitsMissing) ID() string { return "res/limits-missing" }
func (r limitsMissing) Check(c *Context, obj *model.Object) []Finding {
	if !c.To.QuotasEnforced {
		return nil
	}
	var out []Finding
	for _, ps := range obj.PodSpecs() {
		for _, ct := range ps.Containers() {
			res, _ := ct.Spec["resources"].(map[string]any)
			var missing []string
			for _, k := range []string{"requests", "limits"} {
				m, _ := res[k].(map[string]any)
				if m["cpu"] == nil {
					missing = append(missing, k+".cpu")
				}
				if m["memory"] == nil {
					missing = append(missing, k+".memory")
				}
			}
			if len(missing) > 0 {
				out = append(out, c.finding(r.ID(), Error, obj, ct.Path+".resources",
					fmt.Sprintf("container %q is missing %s; the target project enforces ResourceQuota", ct.Name, strings.Join(missing, ", ")), false))
			}
		}
	}
	return out
}
