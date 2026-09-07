#!/usr/bin/env python3
"""Regenerates site/index.html from real kubeport output.

Run from the repo root after `make build`:
    python3 site/build.py
The page never shows invented output: every transcript below is produced by
bin/kubeport on fixtures/k3s-app at build time.
"""
import html
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "bin", "kubeport")
ENV = dict(os.environ, NO_COLOR="1")

TARGETS = [
    ("k3s:1.31", "k3s 1.31", "home"),
    ("openshift:4.19/vsphere", "OpenShift 4.19", "vSphere"),
    ("k8s:1.32/eks", "Kubernetes 1.32", "Amazon EKS"),
    ("k8s:1.34/talos", "Kubernetes 1.34", "Talos, PSA restricted"),
]


def run(*args, cwd=ROOT):
    p = subprocess.run([BIN, *args], cwd=cwd, env=ENV, capture_output=True, text=True)
    if p.returncode == 2:
        sys.exit(f"kubeport failed: {p.stderr}")
    return p.stdout


def esc(s):
    return html.escape(s, quote=False)


def check_html(text):
    """Colourise a `kubeport check` transcript."""
    out = []
    for line in text.rstrip("\n").split("\n"):
        if line.startswith("kubeport "):
            out.append(f'<span class="t-head">{esc(line)}</span>')
        elif line.startswith("ERROR"):
            m = re.match(r"(ERROR)\s+(\S+)\s+(\S+)(?:\s+(\S+))?$", line)
            out.append(fmt_finding("err", m, line))
        elif line.startswith("WARN"):
            m = re.match(r"(WARN)\s+(\S+)\s+(\S+)(?:\s+(\S+))?$", line)
            out.append(fmt_finding("warn", m, line))
        elif line.startswith("INFO"):
            m = re.match(r"(INFO)\s+(\S+)\s+(\S+)(?:\s+(\S+))?$", line)
            out.append(fmt_finding("info", m, line))
        elif line.strip().startswith("fix available:"):
            out.append(f'<span class="t-fix">{esc(line)}</span>')
        elif re.match(r"^\d+ finding", line):
            out.append(f'<span class="t-sum">{esc(line)}</span>')
        elif line.strip() == "no portability findings":
            out.append(f'<span class="t-ok">{esc(line)}</span>')
        else:
            out.append(f'<span class="t-msg">{esc(line)}</span>')
    return "\n".join(out)


def fmt_finding(cls, m, line):
    if not m:
        return f'<span class="t-{cls}">{esc(line)}</span>'
    sev, rule, obj, path = m.groups()
    s = f'<span class="t-{cls}">{sev:<5}</span>  <span class="t-rule">{esc(rule):<32}</span> <span class="t-obj">{esc(obj)}</span>'
    if path:
        s += f'  <span class="t-path">{esc(path)}</span>'
    return s


def diff_html(text):
    out = []
    for line in text.rstrip("\n").split("\n"):
        if line.startswith("+++") or line.startswith("---"):
            out.append(f'<span class="d-file">{esc(line)}</span>')
        elif line.startswith("@@"):
            out.append(f'<span class="d-hunk">{esc(line)}</span>')
        elif line.startswith("+"):
            out.append(f'<span class="d-add">{esc(line)}</span>')
        elif line.startswith("-"):
            out.append(f'<span class="d-del">{esc(line)}</span>')
        else:
            out.append(esc(line))
    return "\n".join(out)


def main():
    if not os.path.exists(BIN):
        sys.exit("build bin/kubeport first (make build)")

    version = run("version").split()[-1]
    tabs, panes = [], []
    for i, (spec, name, sub) in enumerate(TARGETS):
        text = run("check", "--from", "k3s:1.31", "--to", spec, "fixtures/k3s-app")
        text = text.replace(" · kubeport explain <rule> for details", "")
        m = re.search(r"\((\d+) error, (\d+) warn, (\d+) info\)", text)
        errors, warns, infos = (int(x) for x in m.groups()) if m else (0, 0, 0)
        verdict = "blocked" if errors else ("review" if warns else "compatible")
        active = " is-active" if i == 1 else ""
        tabs.append(
            f'<button class="tab{active}" role="tab" id="tab-{i}" aria-controls="pane-{i}" aria-selected="{"true" if i == 1 else "false"}" data-target="{esc(spec)}">'
            f'<span class="tab-flag">--to {esc(spec)}</span><span class="tab-row"><span class="tab-name">{esc(name)}<small>{esc(sub)}</small></span>'
            f'<span class="tab-verdict v-{verdict}" aria-label="{errors} errors, {warns} warnings">{errors}·{warns}·{infos}</span></span></button>'
        )
        hidden = "" if i == 1 else " hidden"
        panes.append(f'<pre class="term-out" id="pane-{i}" role="tabpanel" aria-labelledby="tab-{i}"{hidden}>{check_html(text)}</pre>')

    # translate: dry run against a scratch copy so the fixtures stay pristine
    with tempfile.TemporaryDirectory() as tmp:
        shutil.copytree(os.path.join(ROOT, "fixtures", "k3s-app"), os.path.join(tmp, "deploy"))
        tr = run("translate", "--to", "openshift:4.19/vsphere", "deploy", cwd=tmp)
    head, _, rest = tr.partition("\n\n")
    changes, _, rest = rest.partition("\n\n")
    if rest.startswith("  manual follow-up:"):
        notes, _, rest = rest.partition("\n\n")
    else:
        notes = ""
    diff = rest.split("\n\n  (dry run")[0]
    # Keep the diff to deployment.yaml and service.yaml for the page.
    keep = []
    current = None
    for line in diff.split("\n"):
        if line.startswith("--- a/"):
            current = line
        if current and ("deployment.yaml" in current or "service.yaml" in current):
            keep.append(line)
    diff = "\n".join(keep)
    diff = re.sub(r"a/[^ ]*?deploy/", "a/deploy/", diff)
    diff = re.sub(r"b/[^ ]*?deploy/", "b/deploy/", diff)

    changes_html = []
    for line in changes.split("\n"):
        m = re.match(r"\s+(\S+)\s+(\S+)\s+(.*)$", line)
        if m:
            changes_html.append(f'<span class="t-obj">{esc(m.group(1)):<30}</span> <span class="t-rule">{esc(m.group(2)):<30}</span> <span class="t-msg">{esc(m.group(3))}</span>')
    notes_html = "\n".join(f'<span class="t-note">{esc(l)}</span>' for l in notes.split("\n") if l.strip() and "manual follow-up" not in l)

    rules_txt = run("rules")
    rules = []
    for line in rules_txt.split("\n"):
        m = re.match(r"([F ]) (\S+)\s+(.*)$", line)
        if m:
            rules.append((m.group(2), m.group(3), m.group(1) == "F"))
    cats = {"sec": "Security context and admission", "net": "Networking", "stor": "Storage", "img": "Images", "api": "API versions", "ocp": "OpenShift objects", "k3s": "k3s add-ons", "res": "Resources"}
    rules_html = []
    for cat, title in cats.items():
        items = [r for r in rules if r[0].startswith(cat + "/")]
        li = "".join(
            f'<li><code>{esc(rid)}</code>{"<span class=\"fixmark\" title=\"autofix available\">fix</span>" if fix else ""}<span>{esc(t)}</span></li>'
            for rid, t, fix in items
        )
        rules_html.append(f'<div class="rule-group"><h3>{title}</h3><ul>{li}</ul></div>')

    tpl = open(os.path.join(ROOT, "site", "template.html"), encoding="utf-8").read()
    page = (
        tpl.replace("{{VERSION}}", esc(version))
        .replace("{{TABS}}", "\n".join(tabs))
        .replace("{{PANES}}", "\n".join(panes))
        .replace("{{TR_HEAD}}", esc(head))
        .replace("{{TR_CHANGES}}", "\n".join(changes_html))
        .replace("{{TR_NOTES}}", notes_html)
        .replace("{{TR_DIFF}}", diff_html(diff))
        .replace("{{RULES}}", "\n".join(rules_html))
        .replace("{{RULE_COUNT}}", str(len(rules)))
    )
    if "—" in page:
        sys.exit("em-dash found in generated page")
    open(os.path.join(ROOT, "site", "index.html"), "w", encoding="utf-8").write(page)
    print("wrote site/index.html", len(page), "bytes")


if __name__ == "__main__":
    main()
