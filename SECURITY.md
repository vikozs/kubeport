# Security policy

Kubeport reads manifests and writes files you ask it to write. It never talks to a cluster, never needs credentials, and makes no network calls (Helm and Kustomize rendering are delegated to the binaries already on your PATH).

Report vulnerabilities privately to security@kosir.info. You will get an acknowledgement within 72 hours. Please do not open public issues for security reports.

Releases are built by GitHub Actions with goreleaser, ship an SBOM, and their checksums are signed with cosign (keyless, Sigstore). Verification instructions are in every release's notes.
