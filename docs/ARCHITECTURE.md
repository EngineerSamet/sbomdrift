# sbomdrift — Locked Architecture & Tooling Decisions

> This is the anchor document. Before writing or changing any code, it is decided here first.
> If, mid-build, anything feels tangled, the rule is: re-read this file, and either the code is
> wrong or this file is — fix whichever, but the two never drift silently.

Status: **locked 14 July 2026.** Changes require an explicit note in the "Amendments" section at
the bottom, with a date and a reason.

---

## 0. One-paragraph statement

Two published, independently useful artefacts under one supply-chain-integrity theme:

1. **`sealed-build`** — a *hardened* GitHub Action that builds a container image and produces a
   signed SBOM + vulnerability attestation, with the entire tool chain pinned to commit SHAs and
   run under least privilege. Its reason to exist is not "it runs Syft/Trivy/Cosign" (GitHub's own
   `actions/attest` already does keyless SBOM signing); it is that the chain is built to survive a
   supply-chain attack on the tools themselves — the exact failure the March 2026 `trivy-action`
   compromise demonstrated at scale.
2. **`sbomdrift`** *(flagship)* — a `pip install`-able CLI that answers one question nobody else
   answers without a server: **what became vulnerable since last time?** It stores SBOM component
   inventories over time, re-evaluates them as vulnerability data changes, and reports the **diff** —
   the drift. Not "what is vulnerable now" (solved by Grype, Trivy, sbomgr, bomctl); *what changed.*

Both are proven live on a real AWS account: a fleet of real images in **ECR**, with **AWS Inspector**
enhanced scanning enabled on the same fleet as a **ground-truth referee** to measure sbomdrift against.

The two are chained by narrative, not by dependency: `sealed-build` is *a* nice source of signed
SBOMs; `sbomdrift` eats *any* SBOM. Neither holds the other hostage.

**Guiding principle (the through-line — say this in the interview):** *no long-lived secrets
anywhere.* The same stance recurs at three independent surfaces — **OIDC → short-lived STS** for AWS,
**keyless Sigstore** for signing, **PyPI Trusted Publishing (OIDC)** for release. This is not "I used
some nice tools"; it is one engineering position applied consistently. Every credential in this project
is short-lived and identity-bound.

---

## 1. What ships in the report (v1, by 20 July) vs what continues after

| Deliverable | In the report (v1) | Continues after 20 July |
|---|---|---|
| `sealed-build` Action | **Complete & published** to GitHub Marketplace | hardening tweaks, more registries |
| `sbomdrift` CLI | **Drift core working**: ingest → store → re-evaluate → diff | richer queries, VEX, packaging polish |
| AWS proof | ECR fleet + Inspector + OIDC, **evaluation table done** | more images, longer drift history |

"Complete, no gaps" applies to the **project arc**; the report documents the coherent working slice
that exists by 20 July. This reconciles the hard report deadline with the intent to keep building.

---

## 2. Tool lock — with the reason and the rejected alternative

Every row is a decision. A choice with no rejected alternative was not a choice.

### 2.1 `sbomdrift` CLI

| Concern | Chosen | Rejected / why |
|---|---|---|
| Language | **Python 3.11** | Go (syft/grype/bomctl/sbomgr are all Go). Rejected *because* everything is Go — Python is the positioning gap on PyPI, and it is the one language Samet already knows. |
| Vulnerability oracle | **OSV.dev HTTP API** — batch mode | Bundling Grype's DB. The CLI's novelty is **not** scanning — it is storage + re-evaluation + diff. OSV is free, public, PURL-native, needs no local DB management, and is pure HTTP → keeps the tool pure-Python. **Query pattern: `POST /v1/querybatch` (up to 1000 components/request, returns only vuln IDs + `modified`), then hydrate only the hits via `/v1/vulns/{id}`.** Per-component querying would be thousands of round-trips across a fleet — a design smell. A 2000-package SBOM = ~2 batch calls + a few dozen detail fetches, well under 2s. Grype/Trivy JSON can *also* be ingested for users who already run them. |
| Persistent store (local) | **SQLite** (single file) | Postgres/a server. A server would contradict the "serverless, CI-native" positioning. SQLite is the file-based store that makes drift possible with zero infrastructure (bomctl set the precedent). |
| **State between CI runs** | **S3 bucket** (via the OIDC role we already create) | *The load-bearing question the first draft missed: GitHub runners are ephemeral — where does the SQLite/history live between runs?* Options weighed: commit to repo (diffable but ugly), Actions cache (7-day eviction — fatal for drift), artifacts (90-day, clumsy to read back). **S3 wins:** it makes the AWS part load-bearing rather than decorative, costs pennies, and a bucket is not a server so the "serverless" positioning holds. The CLI pulls the DB from S3 at start, pushes it back at end. Same bucket also holds Terraform remote state — but the CI OIDC role is **prefix-scoped**: it may write `s3://<bucket>/drift/*` and must not touch `s3://<bucket>/tfstate/*`. A real least-privilege detail, on-theme, one sentence in the report. |
| License | **Apache-2.0**, `LICENSE` file + SPDX headers | Both PyPI and the Marketplace require a license; and SPDX hygiene is thematically on-point for a supply-chain project. |
| SBOM parsing | **`lib4sbom`** (reads CycloneDX + SPDX) | Hand-rolling a parser. Rejected — reinventing a solved, fiddly thing. |
| CLI framework | **Typer** | argparse (more boilerplate), Click (Typer wraps it with type hints — cleaner for a beginner to read and defend). |
| Packaging / publish | **`uv` + `pyproject.toml`**, publish to PyPI via **Trusted Publishing (OIDC)** | A PyPI API token in a secret. Rejected on principle: this project's whole thesis is *no long-lived secrets*. Trusted Publishing lets GitHub Actions publish with a short-lived OIDC identity — the CLI practises what it preaches. |
| Tests | **pytest** | — |

### 2.2 `sealed-build` Action

| Concern | Chosen | Rejected / why |
|---|---|---|
| Form | **Composite GitHub Action** | Docker action (slower cold start), JS action (needs a build step). Composite is transparent — a reviewer reads exactly what runs. |
| SBOM generation | **anchore/sbom-action (Syft)**, SHA-pinned | Rolling our own. |
| Vulnerability scan | **aquasecurity/trivy-action, pinned to a full commit SHA** | Pinning to a *tag*. This is the entire point: the March 2026 attack force-pushed malware to 76 of 77 trivy-action **tags**. A tag is mutable; a SHA is not. Pinning to SHA is the concrete, demonstrable lesson. |
| Signing / attestation | **`actions/attest` (keyless, Sigstore)** | Key-based signing (a private key to manage/leak). Keyless removes the key entirely. |
| Cloud auth | **OIDC → short-lived STS** | Long-lived AWS keys in secrets — the exact class of credential the attack harvested. |
| Enforcement | **policy gate: fail on threshold + require verified attestation before push** | Scanning after push (the bad image is already in the registry). |
| Keeping SHA pins fresh | **Dependabot** on the Action repo | The obvious counter to "pin everything to a SHA": *then you never get security updates.* Dependabot understands SHA-pinned actions and bumps them (with a version comment), so the chain is **pinned but not frozen**. This closes the loop and pre-empts the interview question. |
| License | **Apache-2.0** + SPDX headers | Marketplace requires it; consistent with the CLI. |

### 2.3 AWS (the live proof) — all via Terraform

| Concern | Chosen | Reason / rejected |
|---|---|---|
| Region | **us-east-1 (N. Virginia)** | The account already defaults here; it is the cheapest region and gets features first (Inspector, ECR enhanced scanning all present). Value matters less than being *decided and written down* — it hardens into the bucket name, the OIDC role ARN, and every ECR URI. Rejected: eu-central-1 (lower latency from Turkey, but marginally pricier and not where the account is). |
| Human / CLI identity | **IAM user (MFA) → `sts:AssumeRole` into an admin role gated by `aws:MultiFactorAuthPresent=true`** | Rejected #1: **plain IAM user + admin access key** — a static secret that alone can do everything; refutes §0, the SEC02-BP02 anti-pattern. Rejected #2: **IAM Identity Center** — the *correct* answer in a real organisation and what I would use there, but on a new (post-Jul-2025) **Free-plan** account, enabling it forces creating an **AWS Organization**, which per AWS's own Free Tier docs **expires the $200 credits immediately, upgrades the account to paid, and makes it ineligible to earn more** (confirmed against the Free Tier FAQ + multiple re:Post incident reports). Chosen pattern: the user's access key carries **no permissions** — only the right to assume one role, and that role will not open without a second factor. So the single long-lived artefact is an **identity** bearer, not an **authority** bearer; every credential that actually grants access is short-lived. §0 stays honest — and sharper. The MFA here is not an add-on; it is the mechanism that makes the key harmless if leaked. |
| IaC | **Terraform, AWS provider `~> 6.0`** | Reproducible, cert-aligned (SAA), destroyable. *Corrected from `~> 5.x`:* the v5 pin's only justification was the LocalStack v6 DynamoDB-waiter bug — and we are on **real AWS, not LocalStack**, so that reason does not apply. v6 is the current major (6.5x, GA mid-2025). Pinning a year behind for a reason that no longer holds violates §2's own rule. |
| Remote state | **S3 backend, native S3 locking (`use_lockfile = true`)** | Rejected: **DynamoDB lock table** — deprecated since Terraform 1.11 (HashiCorp's own backend docs: "to be removed in a future minor version"); we run 1.15.x, so DynamoDB is one resource + one IAM surface + one future breakage for nothing. Native lockfile is GA. *Bootstrap (chicken-and-egg):* the state bucket must exist before `terraform init` can use it as a backend — so it is created **by hand in tonight's console session** (versioned, encrypted), not by Terraform. Local state breaks the moment CI also runs `apply`. |
| Registry / fleet | **ECR** | The fleet is seeded two ways: (a) **pull-through cache** to auto-pull ~20 real upstream images; (b) **old-tag time machine** — push a 2024 digest *and* today's digest of the same image so drift has *already happened* and can be demoed on day one. |
| SBOM discovery | **ECR OCI 1.1 referrers** where present, **Syft fallback** where not | *Assumption to verify empirically before relying on it:* not every upstream image carries an SBOM referrer, and pull-through-cache referrer sync is a very new feature. We test with 2–3 images first (`aws ecr describe-images` / referrers API); if sync doesn't populate, we generate SBOMs with Syft ourselves. No architecture depends on the sync working. |
| Ground-truth referee | **AWS Inspector enhanced scanning on ECR** | Inspector already does drift (auto re-scan on new CVEs) → it is our **nearest competitor, not OWASP**. *Honest scope of the comparison:* in 5 days we can measure **oracle agreement** — do OSV.dev and Inspector flag the same components on the same fleet? (agreement rate, misses each way, timing). We **cannot** measure a live *drift* comparison — that needs two eval points with real CVE movement in between, which we do not have. So the section is named **"Oracle agreement: OSV.dev vs Inspector"**, not "drift comparison." Still valuable, still rare in a student project, and *true*. New-account 15-day free trial + ~$0.09/first scan + $0.01/re-scan ⇒ ~$5 total for 20 images. |
| CI → AWS identity | **OIDC federation role** (GitHub → STS), branch-scoped | No static AWS credentials anywhere. |
| Cost hygiene | **ECR lifecycle policy; AWS Budgets alarm; NO VPC, NO NAT gateway, NO ECS, NO VPC endpoints** | *Corrected from the first draft, which copied "3 VPC endpoints" from a cost blog.* There is **no compute inside AWS** — GitHub runners are external and reach ECR over the public internet, so there is no VPC traffic to route and nothing for endpoints to save. Interface endpoints would cost ~$14/mo for zero traffic, and ECR's own docs note that pull-through cache *with* an interface endpoint actually requires a NAT gateway for the first pull — i.e. the endpoints drag the NAT back in. So: no VPC at all. "I removed the VPC because nothing needed it" is a better Terraform story than three copied endpoints. ECR bills per unique compressed layer, so a 20-image fleet sharing base layers is ~$1/mo. |
| Deployment context (optional) | a task definition registered (free) or a task spun up briefly during demo week | Only if time allows, and only *after* the CLI works. Inspector's `ecrImageInUseCount` can then show in-use context. |

---

## 3. Data flow — the drift loop (this is the whole product)

```
   (CI start: pull the SQLite DB from S3 ──────────────┐
    so history survives the ephemeral runner)          │
                                                        ▼
   ┌─ sources of SBOMs ─────────────────────────────┐  DB
   │  ECR referrers  │  a local dir  │  Syft (live)  │
   └──────────────────────┬──────────────────────────┘
                          │  sbomdrift ingest
                          ▼
             ┌───────────────────────────┐
             │  SQLite: component         │   snapshot = (image digest, timestamp,
             │  inventory snapshots       │              [PURLs...])
             └─────────────┬─────────────┘
                          │  sbomdrift eval   (OSV /v1/querybatch → hydrate hits)
                          │                   optional: --as-of <date>
                          ▼
             ┌───────────────────────────┐
             │  SQLite: findings          │   finding = (image, PURL, CVE, severity,
             │  over time                 │              first_seen, last_seen)
             └─────────────┬─────────────┘
                          │  sbomdrift diff
                          ▼
        ┌──────────────────────────────────────────┐
        │  DRIFT REPORT                              │
        │   + newly vulnerable   (CVE appeared)      │
        │   - newly fixed        (CVE resolved)      │
        │   ~ new images / removed images            │
        └─────────────┬────────────────────────────┘
                     │  ├─► human-readable table (terminal)
                     │  └─► CI mode: exit non-zero + annotate on new CRITICAL drift
                     ▼
        (CI end: push the updated DB back to S3)
```

The value is entirely in the **persistence + re-evaluation + diff**. A one-shot scanner cannot
produce the DRIFT box because it has no memory of yesterday — and the memory lives in S3, not on the
runner.

**Two distinct kinds of drift — do not conflate them (the first draft did):**

- **Version drift** — *what changed when the base image moved.* Produced by the "old-tag time machine":
  push a 2024 digest and today's digest of `python:3.11-slim`; the diff is real and demoable on day one.
- **Time drift** — *what became vulnerable as advisories were published, at a fixed component set.*
  Produced by `sbomdrift eval --as-of <date>`: OSV records carry `published`/`modified`, so evaluating
  "as of 2026-03-01" then diffing against "today" reconstructs real temporal drift **from real data,
  with no waiting**. Not a trick — a legitimate feature, and it makes drift **deterministically
  testable** (pytest can assert an exact diff), which is the single smartest thing to add to the CLI.

---

## 4. Honest positioning (the report must state this plainly — it is an asset, not a weakness)

| Existing tool | What it does | Why sbomdrift is not redundant |
|---|---|---|
| Grype / Trivy | scan an image or a stored SBOM against a current DB | answer "vulnerable **now**"; no memory, no diff |
| sbomgr / sbom-utility / bomctl | grep / SQL-query / cache SBOMs | answer "which SBOM contains **X**"; not "what **changed**" |
| OWASP Dependency-Track | ingest SBOMs, continuously re-evaluate, **does** drift | needs a running server + DB + frontend; sbomdrift is one CLI + one SQLite file, CI-native, no server |
| **AWS Inspector (ECR)** | **does drift**, auto re-scans on new CVEs | **nearest competitor.** AWS-locked, per-scan priced. sbomdrift: any registry, free, portable — and we *measure* the overlap with a live **oracle-agreement** evaluation (§2.3) |

If a reviewer asks "why does this exist when Inspector/Dependency-Track do it?", the answer is on
this table and backed by the oracle-agreement section. That is the difference between a student
project and an engineering decision.

---

## 5. Repository shape

For now a monorepo; split into two published repos at release (Marketplace wants the Action at a
repo root; PyPI wants the CLI packaged cleanly).

```
sbomdrift/
  cli/            the sbomdrift Python package  → PyPI
  action/         the sealed-build composite Action → GitHub Marketplace (own repo at release)
  infra/          Terraform: ECR, Inspector, OIDC role, budgets (no VPC, no endpoints)
  docs/           this file, ADRs, the evaluation write-up
```

---

## 6. Known risks & how each is bounded

| Risk | Bound |
|---|---|
| Report deadline is ~5 days | v1 scope (§1) is deliberately the working slice; CLI polish is post-deadline |
| ECR referrer sync is very new / may not populate | verify with 2–3 images first; Syft fallback; nothing depends on it |
| OIDC trust policy fails on first try (unhelpful errors) | first task of AWS day; fail early |
| OSV.dev coverage differs from Inspector | that *is* the evaluation — measured, not hidden |
| Scope creep back into "platform" | this document; anything not here is out |
| Timeline is ~2× a beginner's realistic pace over 5 days | **cut order (first to go): the VPC (already deleted) → timebox ECR referrer-sync to 60 min then fall back to Syft → the Action's "more registries" is post-deadline. Do NOT cut the Marketplace publish — it is the one cheap, verifiable proof.** `--as-of` de-risks the CLI by making drift demoable without waiting. |
| CV reads as "platform/security eng", not "DevOps"; gaps in monitoring & K8s | accepted and deliberate. Post-deadline, on-theme fills: remote state (already needed) + export the drift metrics the CLI naturally emits to a dashboard. Do **not** bolt K8s on — that is a separate project. Write CV bullets as **outcome, not topic**. |

---

## Amendments

**2026-07-14 — review pass (7 corrections to the initial lock):**

1. **Deleted the VPC and all VPC endpoints.** No compute lives in AWS; GitHub runners hit ECR over the
   public internet, so there is nothing to route and endpoints save nothing (and PTC + interface
   endpoint would *require* a NAT). Reason in the first draft was copied from a cost blog; removed.
2. **Added the missing state-persistence answer: S3.** The first draft never said where the SQLite
   history lives between ephemeral CI runs — the whole product depends on it. The CLI now pulls/pushes
   its DB from an S3 bucket (same bucket as Terraform remote state), making AWS load-bearing.
3. **OSV query pattern fixed** from per-component (thousands of round-trips) to `POST /v1/querybatch`
   + hydrate-hits. Was a scalability smell.
4. **Provider pin changed `~> 5.x` → `~> 6.0`.** The v5 reason (LocalStack waiter bug) does not apply
   on real AWS; pinning a year behind for a dead reason broke §2's own rule.
5. **Evaluation renamed** "drift comparison" → **"Oracle agreement: OSV.dev vs Inspector."** In 5 days
   we can honestly measure oracle overlap, not a live drift comparison.
6. **Added `--as-of` (time drift) and separated it from version drift (old-tag trick).** Reconstructs
   real temporal drift from OSV `published`/`modified` timestamps with no waiting; makes drift
   deterministically unit-testable.
7. **Added: LICENSE (Apache-2.0) for both artefacts; Dependabot on the Action to keep SHA pins fresh
   (pinned-but-not-frozen); Terraform remote state.** Also elevated the "no long-lived secrets"
   through-line to a stated §0 principle.

**2026-07-15 — second review pass (4 open decisions closed + 1 leak fixed):**

1. **Human/CLI identity = IAM Identity Center, NOT an IAM-user access key.** A long-lived access key
   in `~/.aws/credentials` refutes §0 and is the AWS SEC02-BP02 anti-pattern. `aws sso login` gives
   short-lived creds; no static key. This was hiding in a parenthetical — now a §2.3 row with its
   rejected alternative, per §2's own rule.
2. **Region locked: us-east-1.** Was absent from the doc entirely; it hardens into bucket names, the
   OIDC ARN, and every ECR URI, so it must be decided, not discovered.
3. **State locking: `use_lockfile = true`, DynamoDB lock table removed.** `dynamodb_table` is
   deprecated since TF 1.11; keeping it repeated Amendment 4's own mistake (stale tech, no rejected
   alternative).
4. **Bootstrap documented:** the state bucket is created by hand in the console session, before
   `terraform init`, resolving the chicken-and-egg the first draft ignored.
5. **Leak fixed:** §5 repo shape still listed "VPC endpoints" under `infra/` after Amendment 1 deleted
   them — the exact silent same-document drift this file's preamble warns against. Rule wasn't enough;
   the check caught it.
6. Added: CI OIDC role is **prefix-scoped** on the shared bucket (`drift/*` yes, `tfstate/*` no).

**2026-07-24 — implementation pass (6 corrections, all found by building the thing):**

1. **Region changed `us-east-1` → `eu-central-1`.** §2.3 justified us-east-1 with "the account
   already defaults here." Checked during infrastructure work: the account's configured region is
   **eu-central-1** and its only pre-existing bucket is in eu-north-1. The stated reason was simply
   false. Under this file's own rule the conclusion could not be inherited, so the choice was
   re-made: eu-central-1 is nearest to the operator and carries ECR, Inspector and OIDC. Rejected:
   keeping us-east-1 for marginal price and feature-lead — real, but not worth a decision resting on
   a premise that does not hold.
2. **Findings are keyed on the *versionless* PURL, not the full one.** The first real comparison of
   two `python:3.11-slim` releases reported *115 components added, 114 removed, 0 unchanged* — every
   finding simultaneously new and fixed, because `openssl@1.1.1n` and `openssl@3.5.6` are different
   strings. Identity is the package; version is an attribute of it. Same data, after the fix: 22
   newly vulnerable, 101 newly fixed, 59 unchanged, 76 upgraded. **105 green tests did not catch
   this**, because the tests were written from the same wrong model.
3. **PURL type and namespace are lower-cased on ingest.** One Syft document contains both
   `pkg:deb/debian/...` and `pkg:deb/Debian/...`; the purl spec makes those the same package and
   string equality did not, so one package was counted twice.
4. **Non-package SBOM entries are skipped, not counted as unmapped.** Syft catalogues 483 *files*
   beside 130 packages in `python:3.11-slim`; treating a file entry as "a package we failed to
   identify" reported 22% PURL coverage for an ingest that had actually mapped 92%.
5. **OSV `aliases` are stored and used for matching (schema v2).** Comparing against a second oracle
   by raw identifier scored 70 agreements / 90 OSV-only — a chasm that was largely an artefact,
   since the same flaw is `GHSA-…`, `PYSEC-…` and `CVE-…` to three different databases. With aliases
   resolved: 80 / 70 / 3, Jaccard 0.52. *A measurement that flattered the tool was wrong; that is
   the one to distrust first.*
6. **Oracle referee changed: Inspector → Trivy over identical SBOMs.** §2.3 planned an
   OSV-vs-Inspector agreement measurement. Running Trivy against the *same SBOM files* isolates the
   variable properly — both oracles see an identical component list, so any difference is the
   vulnerability database and not what each tool detected in the image. Inspector remains in
   `infra/` behind `enable_inspector`, defaulting to off; it was the documented first cut and it was
   cut. Also: the ECR pull-through cache is now opt-in, because it is the one place in the project
   that requires a stored long-lived credential (Docker Hub offers no OIDC), and a default
   `terraform apply` should create neither a charge nor a secret.

**Still outstanding (not done, not pretended):** the state bucket has not been bootstrapped and no
MFA device is registered on the IAM user, so `terraform apply` has not been run — `validate` passes
and that is all that is claimed. The user remains in the account's `admin` group; §2.3's identity
model is written but not yet in force.

**2026-07-15 (later, before the console session) — identity model corrected a SECOND time (my error, caught before the click):**
I had chosen IAM Identity Center. On a new Free-plan account, enabling it creates an **AWS Organization**,
and AWS's own Free Tier docs are explicit: joining an Organization **expires the $200 credits immediately,
upgrades to paid, and makes the account ineligible for more** — irreversible without a Support ticket
(multiple re:Post incident reports confirm). An `account instance` of Identity Center avoids the
Organization but **cannot issue permission sets / AWS-account access**, so it is useless for CLI identity.
Corrected to: **IAM user (MFA) whose only permission is `sts:AssumeRole` into an admin role gated by
`aws:MultiFactorAuthPresent=true`.** The access key is an *identity* bearer, not an *authority* bearer —
harmless if leaked because it opens nothing without the second factor. §0 holds and is sharper. The
$15 this project will spend does not justify burning $200 of a 12-month learning runway for purity.
