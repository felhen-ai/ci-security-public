---
title: Felhen Secret Scan
kind: reference
area: development
project: ci-security-public
collection: felhen-ci-security-public
owner: felhen-ai
status: current
canonical: README.md
globalRef: github://felhen-ai/ci-security-public/README.md
reviewCadenceDays: 90
lastReviewedAt: 2026-11-04
sourceRefs:
  - https://github.com/felhen-ai/ci-security-public
related:
  - action.yml
  - gitleaks.toml
  - .github/workflows/secret-scan.yml
supersedes: []
supersededBy: []
sensitivity: public
---

# Felhen secret scan

This public composite action scans the Git range supplied by the caller and reports findings in the caller job's `secret-scan` context.

## Usage

Pin the action to an immutable reviewed commit SHA. Replace `<IMMUTABLE_COMMIT_SHA>` only after the action repository's default branch has been merged and its commit ancestry has been verified.

```yaml
name: Secret scan

on:
  pull_request:

permissions:
  contents: read

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          fetch-depth: 0
          persist-credentials: false
      - uses: felhen-ai/ci-security-public@<IMMUTABLE_COMMIT_SHA>
        with:
          base-ref: ${{ github.event.pull_request.base.sha }}
          head-ref: ${{ github.event.pull_request.head.sha }}
```

For pull requests, pass the event's explicit base and head commit SHAs and use a full checkout so the supplied range is available locally. The composite action adds its scan result to the job summary; the workflow job supplies the `secret-scan` check context. For a push workflow, pass the reviewed before and after commit SHAs for that event.

## Reviewed synthetic fixtures

The repository's test fixtures intentionally exercise detector rules. Their reviewed, exact fingerprints are listed in `.gitleaksignore`; this is not a general exclusion. Do not add paths, broad patterns, or inline allow markers to suppress findings. If a finding is not a reviewed synthetic fixture, do not publish the secret value: revoke or rotate it through the appropriate secure process, then report only the rule, file, line, commit, and fingerprint needed for review.

## Public repository

Canonical repository: https://github.com/felhen-ai/ci-security-public
