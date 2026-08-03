# Verifying a release

Release images and artifacts are signed with
[cosign](https://github.com/sigstore/cosign) keyless signing. There is no public
key to distribute: the signature carries a short-lived Sigstore certificate
proving which GitHub workflow, in which repository, at which tag produced the
artifact.

!!! danger "Both certificate flags are required"

    `cosign verify` without `--certificate-identity` and
    `--certificate-oidc-issuer` accepts a signature from **any** identity. That is
    the most common way this check gets run, and it proves nothing.

## The image

```bash
IMAGE=ghcr.io/phonginreallife/kernelseal
VERSION=v1.2.0
IDENTITY="https://github.com/phonginreallife/kernelseal/.github/workflows/release.yaml@refs/tags/${VERSION}"

cosign verify \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "${IMAGE}:${VERSION}"
```

Signatures attach to the image **digest** rather than the tag, because a tag can
be moved to a different image afterwards while a digest cannot. To pin what you
verified, resolve the digest and deploy that:

```bash
crane digest "${IMAGE}:${VERSION}"    # sha256:...
```

## The release archives

One signature covers every tarball, because what it signs is the file containing
their hashes:

```bash
cosign verify-blob \
  --bundle checksums.txt.cosign.bundle \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

sha256sum -c checksums.txt
```

## The SBOM

Every release publishes an SPDX SBOM, both as a release asset
(`kernelseal-<version>-sbom.spdx.json`) and as a cosign attestation on the image,
so a cluster that only knows the digest can still recover it:

```bash
cosign verify-attestation \
  --type spdxjson \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "${IMAGE}:${VERSION}" | jq -r '.payload' | base64 -d | jq '.predicate' > sbom.json

grype sbom:sbom.json
```

## What CI checks on every change

| Check | Tool |
|---|---|
| Dependency vulnerabilities | govulncheck |
| Container vulnerabilities | Trivy |
| Code security issues | gosec, CodeQL |
| Secret detection | Gitleaks, TruffleHog |
| Dockerfile lint | Hadolint |
| BPF and Go struct layout agreement | `make abi-check` |

The weekly scheduled run scans the full git history for secrets; pushes scan the
push range.
