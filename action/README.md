# sealed-build

A GitHub Action that builds a container image, produces an SBOM, **refuses to push
it if it fails a vulnerability threshold**, and signs the result with keyless
attestation — with every third-party step pinned to an immutable commit SHA.

## Why this exists

GitHub's own `actions/attest` already does keyless SBOM signing, so signing is not
the gap. The gap is **trusting the chain that produces the evidence**.

In March 2026 an attacker force-pushed malicious code over 76 of the 77 release
*tags* of `aquasecurity/trivy-action`. Every workflow that referenced `@v0.28.0`
began running the attacker's code — including the workflows whose job was to catch
exactly this. A tag is a mutable pointer. A commit SHA is content-addressed and
cannot be moved.

Every step in this Action is pinned to a full 40-character SHA, and
[Dependabot](../.github/dependabot.yml) raises a reviewable pull request when a
pin should move. **Pinned, but not frozen** — which is the answer to the obvious
objection that pinning means never receiving security updates.

## Use

```yaml
permissions:
  contents: read
  id-token: write      # keyless signing
  attestations: write

steps:
  - uses: actions/checkout@v5
  - uses: EngineerSamet/sbomdrift/action@v0.1.0
    with:
      image-name: ghcr.io/${{ github.repository }}:${{ github.sha }}
      severity-threshold: HIGH
      push: "true"
```

## Inputs

| Input | Default | Description |
|---|---|---|
| `image-name` | *required* | Image reference to build |
| `context` | `.` | Build context |
| `dockerfile` | `Dockerfile` | Dockerfile path within the context |
| `severity-threshold` | `HIGH` | Fail at or above this severity |
| `ignore-unfixed` | `true` | Ignore findings with no available fix |
| `push` | `false` | Push — only ever reached if the gate passes |
| `sbom-format` | `cyclonedx-json` | Syft output format |

## Outputs

| Output | Description |
|---|---|
| `sbom-path` | Path to the generated SBOM |
| `digest` | Digest of the built image |
| `gate-result` | `pass` when the gate allowed the image through |

## The ordering, and why it is what it is

```
build (loaded locally, not pushed)
  └─ SBOM
       └─ vulnerability gate  ◄── fails here, and the image never leaves the runner
            └─ attest the SBOM
                 └─ push
                      └─ attest the image digest in the registry
```

The gate runs **before** the push, because scanning an image that is already in
the registry reports a problem you have already shipped. Image attestation
necessarily comes **after** the push, because an attestation binds to a digest
that exists in a registry — which is safe here, since the gate has already
decided the image is allowed to exist at all.

## Verifying an attestation

```bash
gh attestation verify oci://ghcr.io/owner/app:tag --repo owner/app
```

## Licence

Apache-2.0.
