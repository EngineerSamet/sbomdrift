# sbomdrift

**What became vulnerable since last time?**

Vulnerability scanners answer *what is vulnerable now*. They are stateless, so they
cannot answer the question that actually reaches an on-call engineer: **what changed?**
A build that was clean last Tuesday and is not clean today has a story, and no
one-shot scan can tell it.

`sbomdrift` stores the component inventories described by your SBOMs, re-evaluates
them against [OSV.dev](https://osv.dev), and reports the **diff** between two
evaluations:

```
DRIFT  python:3.11-slim   2026-03-01 → 2026-07-24

  + newly vulnerable   3
      CRITICAL  CVE-2026-1234   pkg:deb/debian/libssl3@3.0.11-1
      HIGH      CVE-2026-2233   pkg:pypi/requests@2.31.0
      MEDIUM    GHSA-xxxx-yyyy  pkg:pypi/urllib3@2.0.7

  - newly fixed        1
      HIGH      CVE-2025-9999   pkg:deb/debian/zlib1g@1:1.2.13
```

It is one `pip install`, one SQLite file and no server.

## Install

```bash
pip install sbomdrift        # or: uv tool install sbomdrift
```

## Use

```bash
# 1. Remember what an artefact contained
sbomdrift ingest sbom.cdx.json --artefact python:3.11-slim

# 2. Ask the oracle — twice, at two points in time
sbomdrift eval --as-of 2026-03-01 --label march
sbomdrift eval --label today

# 3. What changed?
sbomdrift diff --from march --to today
```

In CI, `--fail-on HIGH` makes the command exit non-zero when drift introduces a new
finding at or above that severity — so a pipeline breaks on *new* risk rather than on
the accumulated backlog it already knew about.

## Two kinds of drift

| Kind | What it answers | How |
|---|---|---|
| **Version drift** | what changed when the artefact moved | two snapshots (different digests), one evaluation date |
| **Time drift** | what became vulnerable while the artefact stood still | one snapshot, two evaluation dates (`--as-of`) |

`--as-of` reconstructs history from OSV's own `published` timestamps, so temporal
drift is demonstrable immediately instead of after a month of waiting — and it makes
drift **deterministically testable**, which is why the test suite can assert an exact
diff.

*Caveat, stated plainly:* OSV records are amended over time. `--as-of` filters on
publication date, so it reconstructs *when an advisory became known*, not the exact
data an evaluation would have returned on that day.

## Where the history lives

The store is a single SQLite file. CI runners are ephemeral, so `sbomdrift` can pull
that file from S3 at the start of a run and push it back at the end:

```bash
sbomdrift pull s3://my-bucket/drift/history.db
... ingest / eval / diff ...
sbomdrift push s3://my-bucket/drift/history.db
```

Requires the `s3` extra (`pip install "sbomdrift[s3]"`) and credentials from the
standard AWS chain — in GitHub Actions, short-lived OIDC credentials.

## How it compares

| Tool | Answers | Needs |
|---|---|---|
| Grype, Trivy | is this vulnerable **now** | nothing — but no memory, no diff |
| sbomgr, bomctl | which SBOM contains **X** | nothing — but not "what changed" |
| OWASP Dependency-Track | drift, and much more | a server, a database, a frontend |
| AWS Inspector | drift, for images in ECR | an AWS account; per-scan pricing |
| **sbomdrift** | **what changed** | one CLI and one file |

## Licence

Apache-2.0.
