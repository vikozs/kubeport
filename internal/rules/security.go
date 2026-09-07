package rules

import (
	"fmt"
	"strings"

	"github.com/kubeport/kubeport/internal/model"
)

func init() {
	register(runAsRoot{})
	register(fixedUID{})
	register(capabilities{})
	register(privEsc{})
	register(privileged{})
	register(hostNamespaces{})
	register(hostPath{})
	register(seccomp{})
	register(pspUsage{})
	register(sccAnnotation{})
}

// effective returns a security context field, container value winning over pod value.
func effective(pod, ctr map[string]any, key string) (any, bool) {
	if ctr != nil {
		if v, ok := ctr[key]; ok {
			return v, true
		}
	}
	if pod != nil {
		if v, ok := pod[key]; ok {
			return v, true
		}
	}
	return nil, false
}

// ---------------------------------------------------------------- run-as-root
type runAsRoot struct{}

func (runAsRoot) ID() string { return "sec/run-as-root" }
func (r runAsRoot) Check(c *Context, obj *model.Object) []Finding {
	var out []Finding
	for _, ps := range obj.PodSpecs() {
		psc := ps.SecurityContext()
		for _, ct := range ps.Containers() {
			csc := ct.SecurityContext()
			uid, hasUID := effective(psc, csc, "runAsUser")
			nonRoot, hasNonRoot := effective(psc, csc, "runAsNonRoot")
			if hasUID {
				if n, ok := model.Int64(uid); ok && n == 0 {
					sev := Warn
					if c.Strict() {
						sev = Error
					}
					out = append(out, c.finding(r.ID(), sev, obj, ct.Path+".securityContext.runAsUser",
						fmt.Sprintf("container %q runs as UID 0; %s rejects it", ct.Name, admissionName(c)), false))
				}
				continue
			}
			if b, _ := model.Bool(nonRoot); hasNonRoot && b {
				continue
			}
			switch {
			case c.To.Admission == "scc":
				// OpenShift assigns a UID from the project range; the pod starts,
				// but only if the image tolerates a random non-root UID.
				out = append(out, c.finding(r.ID(), Warn, obj, ct.Path+".securityContext",
					fmt.Sprintf("container %q sets neither runAsNonRoot nor runAsUser; %s will run it as an arbitrary UID from the project range, so the image must not require root or a fixed UID", ct.Name, c.To.DefaultSCC), true))
			case c.Strict():
				out = append(out, c.finding(r.ID(), Error, obj, ct.Path+".securityContext",
					fmt.Sprintf("container %q must set runAsNonRoot: true for PSA restricted", ct.Name), true))
			default:
				out = append(out, c.finding(r.ID(), Info, obj, ct.Path+".securityContext",
					fmt.Sprintf("container %q may run as root (image default); this will fail on OpenShift restricted-v2 and PSA restricted", ct.Name), false))
			}
		}
	}
	return out
}

func admissionName(c *Context) string {
	if c.To.Admission == "scc" {
		return "SCC " + c.To.DefaultSCC
	}
	if c.To.Admission == "psa" {
		return "PSA " + c.To.PSALevel
	}
	return "the target"
}

// ------------------------------------------------------------------ fixed-uid
type fixedUID struct{}

func (fixedUID) ID() string { return "sec/fixed-uid" }
func (r fixedUID) Check(c *Context, obj *model.Object) []Finding {
	if !c.To.ArbitraryUID {
		return nil
	}
	var out []Finding
	for _, ps := range obj.PodSpecs() {
		check := func(sc map[string]any, path, who string) {
			if sc == nil {
				return
			}
			if n, ok := model.Int64(sc["runAsUser"]); ok && n != 0 {
				out = append(out, c.finding(r.ID(), Error, obj, path+".runAsUser",
					fmt.Sprintf("%s pins runAsUser=%d; %s assigns UIDs from the project range and rejects fixed UIDs outside it", who, n, c.To.DefaultSCC), true))
			}
			if n, ok := model.Int64(sc["runAsGroup"]); ok && n != 0 {
				out = append(out, c.finding(r.ID(), Warn, obj, path+".runAsGroup",
					fmt.Sprintf("%s pins runAsGroup=%d; %s requires the GID to be in the project range (root group 0 is the portable choice)", who, n, c.To.DefaultSCC), true))
			}
			if n, ok := model.Int64(sc["fsGroup"]); ok && n != 0 {
				out = append(out, c.finding(r.ID(), Warn, obj, path+".fsGroup",
					fmt.Sprintf("%s pins fsGroup=%d; %s requires fsGroup in the project range", who, n, c.To.DefaultSCC), true))
			}
		}
		check(ps.SecurityContext(), ps.Path+".securityContext", "pod")
		for _, ct := range ps.Containers() {
			check(ct.SecurityContext(), ct.Path+".securityContext", "container "+strconvQuote(ct.Name))
		}
	}
	return out
}

func strconvQuote(s string) string { return fmt.Sprintf("%q", s) }

// --------------------------------------------------------------- capabilities
type capabilities struct{}

var dangerousCaps = map[string]bool{
	"SYS_ADMIN": true, "NET_ADMIN": true, "NET_RAW": true, "SYS_PTRACE": true, "SYS_MODULE": true,
	"SYS_RAWIO": true, "SYS_BOOT": true, "SYS_TIME": true, "DAC_OVERRIDE": true, "CHOWN": true,
	"SETUID": true, "SETGID": true, "MKNOD": true, "AUDIT_WRITE": true, "BPF": true, "PERFMON": true,
	"SYS_CHROOT": true, "KILL": true, "FOWNER": true, "FSETID": true, "SETPCAP": true, "SETFCAP": true,
	"ALL": true,
}

func (capabilities) ID() string { return "sec/capabilities" }
func (r capabilities) Check(c *Context, obj *model.Object) []Finding {
	var out []Finding
	for _, ps := range obj.PodSpecs() {
		for _, ct := range ps.Containers() {
			sc := ct.SecurityContext()
			var caps map[string]any
			if sc != nil {
				caps, _ = sc["capabilities"].(map[string]any)
			}
			dropAll := false
			var added []string
			if caps != nil {
				for _, d := range toStrings(caps["drop"]) {
					if strings.EqualFold(d, "ALL") {
						dropAll = true
					}
				}
				added = toStrings(caps["add"])
			}
			if !dropAll {
				sev := Info
				if c.Strict() {
					sev = Error
				}
				out = append(out, c.finding(r.ID(), sev, obj, ct.Path+".securityContext.capabilities.drop",
					fmt.Sprintf("container %q does not drop ALL capabilities", ct.Name), c.Strict()))
			}
			for _, a := range added {
				up := strings.ToUpper(a)
				if up == "NET_BIND_SERVICE" {
					continue
				}
				sev := Info
				if c.Strict() {
					sev = Error
				} else if dangerousCaps[up] && c.Baseline() {
					sev = Warn
				}
				out = append(out, c.finding(r.ID(), sev, obj, ct.Path+".securityContext.capabilities.add",
					fmt.Sprintf("container %q adds capability %s; only NET_BIND_SERVICE is allowed under %s", ct.Name, up, admissionName(c)), false))
			}
		}
	}
	return out
}

func toStrings(v any) []string {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, x := range list {
		out = append(out, model.Str(x))
	}
	return out
}

// ------------------------------------------------------------------- privEsc
type privEsc struct{}

func (privEsc) ID() string { return "sec/allow-privilege-escalation" }
func (r privEsc) Check(c *Context, obj *model.Object) []Finding {
	if !c.Strict() {
		return nil
	}
	var out []Finding
	for _, ps := range obj.PodSpecs() {
		for _, ct := range ps.Containers() {
			sc := ct.SecurityContext()
			if sc != nil {
				if b, ok := model.Bool(sc["allowPrivilegeEscalation"]); ok && !b {
					continue
				}
			}
			out = append(out, c.finding(r.ID(), Error, obj, ct.Path+".securityContext.allowPrivilegeEscalation",
				fmt.Sprintf("container %q must set allowPrivilegeEscalation: false", ct.Name), true))
		}
	}
	return out
}

// ---------------------------------------------------------------- privileged
type privileged struct{}

func (privileged) ID() string { return "sec/privileged" }
func (r privileged) Check(c *Context, obj *model.Object) []Finding {
	var out []Finding
	for _, ps := range obj.PodSpecs() {
		for _, ct := range ps.Containers() {
			sc := ct.SecurityContext()
			if sc == nil {
				continue
			}
			if b, ok := model.Bool(sc["privileged"]); ok && b {
				sev := Info
				msg := fmt.Sprintf("container %q is privileged; allowed here, but needs the privileged SCC or a PSA privileged namespace elsewhere", ct.Name)
				if !c.To.PrivilegedAllowed {
					sev = Error
					msg = fmt.Sprintf("container %q is privileged; %s refuses it (needs the privileged SCC or a PSA privileged namespace)", ct.Name, admissionName(c))
				}
				out = append(out, c.finding(r.ID(), sev, obj, ct.Path+".securityContext.privileged", msg, false))
			}
		}
	}
	return out
}

// ------------------------------------------------------------ hostNamespaces
type hostNamespaces struct{}

func (hostNamespaces) ID() string { return "sec/host-namespaces" }
func (r hostNamespaces) Check(c *Context, obj *model.Object) []Finding {
	var out []Finding
	for _, ps := range obj.PodSpecs() {
		for _, k := range []string{"hostNetwork", "hostPID", "hostIPC"} {
			if b, ok := model.Bool(ps.Spec[k]); ok && b {
				msg := fmt.Sprintf("%s: true is allowed by %s here, refused by OpenShift restricted-v2 and PSA baseline/restricted", k, admissionName(c))
				sev := Info
				if !c.To.PrivilegedAllowed {
					sev = Error
					msg = fmt.Sprintf("%s: true is refused by %s", k, admissionName(c))
				}
				out = append(out, c.finding(r.ID(), sev, obj, ps.Path+"."+k, msg, false))
			}
		}
	}
	return out
}

// ------------------------------------------------------------------ hostPath
type hostPath struct{}

func (hostPath) ID() string { return "sec/hostpath" }
func (r hostPath) Check(c *Context, obj *model.Object) []Finding {
	var out []Finding
	for _, ps := range obj.PodSpecs() {
		for i, v := range ps.Volumes() {
			if hp, ok := v["hostPath"].(map[string]any); ok {
				msg := fmt.Sprintf("volume %q mounts host path %s; allowed by %s here, refused by OpenShift restricted-v2 and PSA baseline/restricted", model.Str(v["name"]), model.Str(hp["path"]), admissionName(c))
				sev := Info
				if !c.To.HostPathAllowed {
					sev = Error
					msg = fmt.Sprintf("volume %q mounts host path %s; refused by %s", model.Str(v["name"]), model.Str(hp["path"]), admissionName(c))
				}
				out = append(out, c.finding(r.ID(), sev, obj, fmt.Sprintf("%s.volumes[%d].hostPath", ps.Path, i), msg, false))
			}
		}
	}
	return out
}

// ------------------------------------------------------------------- seccomp
type seccomp struct{}

func (seccomp) ID() string { return "sec/seccomp-profile" }
func (r seccomp) Check(c *Context, obj *model.Object) []Finding {
	if c.To.Admission != "psa" || c.To.PSALevel != "restricted" {
		return nil
	}
	var out []Finding
	for _, ps := range obj.PodSpecs() {
		psc := ps.SecurityContext()
		podOK := hasSeccomp(psc)
		for _, ct := range ps.Containers() {
			if podOK || hasSeccomp(ct.SecurityContext()) {
				continue
			}
			out = append(out, c.finding(r.ID(), Error, obj, ps.Path+".securityContext.seccompProfile",
				fmt.Sprintf("container %q has no seccompProfile; PSA restricted requires RuntimeDefault or Localhost", ct.Name), true))
			break // one finding per pod is enough
		}
	}
	return out
}

func hasSeccomp(sc map[string]any) bool {
	if sc == nil {
		return false
	}
	sp, ok := sc["seccompProfile"].(map[string]any)
	if !ok {
		return false
	}
	t := model.Str(sp["type"])
	return t == "RuntimeDefault" || t == "Localhost"
}

// ------------------------------------------------------------------ pspUsage
type pspUsage struct{}

func (pspUsage) ID() string { return "sec/psp-usage" }
func (r pspUsage) Check(c *Context, obj *model.Object) []Finding {
	if obj.Kind() != "PodSecurityPolicy" {
		return nil
	}
	sev := Warn
	msg := "PodSecurityPolicy is deprecated and removed in Kubernetes 1.25"
	if c.To.KubeMinor() >= 25 || c.To.IsOpenShift() {
		sev = Error
		msg = "PodSecurityPolicy does not exist on " + c.To.Display + "; use Pod Security Admission labels or an admission controller"
	}
	return []Finding{c.finding(r.ID(), sev, obj, "", msg, false)}
}

// ------------------------------------------------------------- sccAnnotation
type sccAnnotation struct{}

func (sccAnnotation) ID() string { return "sec/scc-annotation" }
func (r sccAnnotation) Check(c *Context, obj *model.Object) []Finding {
	if c.To.IsOpenShift() {
		return nil
	}
	var out []Finding
	if obj.Group() == "security.openshift.io" {
		out = append(out, c.finding(r.ID(), Error, obj, "", fmt.Sprintf("%s is an OpenShift security object; %s has no SCC API", obj.Kind(), c.To.Display), false))
	}
	for k := range obj.Annotations() {
		if strings.HasPrefix(k, "openshift.io/scc") {
			out = append(out, c.finding(r.ID(), Warn, obj, "metadata.annotations."+k, "OpenShift SCC annotation has no effect on "+c.To.Display, false))
		}
	}
	return out
}
