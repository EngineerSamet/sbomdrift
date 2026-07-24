# sbomdrift

**Two artefacts, one question: can you trust what your build produced, and can you
tell what changed since last time?**

| | |
|---|---|
| [**`sbomdrift`**](cli/) — a `pip install`-able CLI | *What became vulnerable since last time?* Stores SBOM component inventories over time, re-evaluates them against OSV.dev, and reports the **diff**. |
| [**`sealed-build`**](action/) — a hardened GitHub Action | Builds an image, produces an SBOM, blocks it on a vulnerability threshold **before** it can reach a registry, and signs it keylessly — with every step pinned to an immutable commit SHA. Released at [EngineerSamet/sealed-build](https://github.com/EngineerSamet/sealed-build) (`v0.1.0`). |

They are joined by a theme, not by a dependency: `sealed-build` is one good source
of SBOMs, and `sbomdrift` eats any SBOM. Neither holds the other hostage.

## The through-line: no long-lived secrets

The same position appears at three independent surfaces, and it is the thing to
argue about if you want to argue about something:

| Surface | Instead of | This project uses |
|---|---|---|
| AWS access | a static access key in CI | **OIDC federation → short-lived STS credentials** |
| Artefact signing | a private key to store and rotate | **keyless Sigstore** — no key exists |
| Package release | a PyPI API token in a repository secret | **Trusted Publishing (OIDC)** |

Every credential in this project is short-lived and identity-bound.

## What drift means, precisely

A scanner answers *"is this vulnerable now?"*. It is stateless, so it cannot answer
the question that actually reaches an engineer: *"what changed?"* sbomdrift keys
findings on `(component identity, vulnerability)` and diffs two **evaluations**,
which makes both kinds of change expressible with one implementation:

* **version drift** — two snapshots, one moment. *The artefact moved.*
* **time drift** — one snapshot, two moments. *The world moved.*

Measured on two real releases of `python:3.11-slim`:

```
DRIFT · version drift · python:3.11.0-slim → python:3.11-slim

  + newly vulnerable    22
  - newly fixed        101      including 4 CRITICAL (openssl, dpkg, libtasn1)
    unchanged           59
  ~ components        +37 added · -38 removed · 76 upgraded
```

## Repository layout

```
cli/         the sbomdrift Python package        → PyPI
action/      the sealed-build composite Action   → GitHub Marketplace
infra/       Terraform: ECR, OIDC role, budgets  (no VPC — nothing runs inside AWS)
demo/        two Dockerfiles: one the gate passes, one it blocks
evaluation/  reproducible measurements, with the raw output committed
docs/        the locked architecture document and its amendment history
samples/     real SBOMs used by the evaluation
```

## Start here

* [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — every tool choice with the
  alternative it beat, and an amendment log recording where the first draft was
  wrong. A choice with no rejected alternative was not a choice.
* [`cli/README.md`](cli/README.md) — install and use the CLI.
* [`action/README.md`](action/README.md) — the Action, and why SHA pinning is the
  entire point.

## Licence

Apache-2.0.
