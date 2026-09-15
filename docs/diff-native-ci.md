# Diff-native CI mode & policy-as-code gate

ECDAT ships an offline `ecdat` CLI for enforcing cryptographic policy in
CI. It combines two capabilities:

1. **Diff-native scanning** — only scan the files that changed since a git
   ref (e.g. the PR base branch), so a merge gate reports on what a change
   *introduced*, not the whole repository.
2. **Policy-as-code gating** — declare rules in a YAML file checked into the
   repo (`ecdat-policy.yaml`) and fail the build when those rules are
   violated.

Both are read-only and offline: ECDAT never fetches, installs, executes, or
mutates anything it scans.

## Installation

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
# The `ecdat` console script is wired in pyproject.toml. To run it in-tree:
python -m app.cli --help
```

## Basic usage

```bash
# Scan the changed files since the base branch and enforce policy.
ecdat scan . --since main --policy ecdat-policy.yaml

# Machine-readable output for CI.
ecdat scan . --since main --policy ecdat-policy.yaml --json

# Re-check policy against an existing scan without re-scanning.
ecdat check-policy . --policy ecdat-policy.yaml
```

### Exit codes

| Code | Meaning                                              |
|------|------------------------------------------------------|
| `0`  | Scan completed and all policy rules satisfied        |
| `1`  | Policy violations found (gate closed)                 |
| `2`  | No policy file found, or no scan found               |

Pass `--no-fail-on-violation` to always exit `0` (report-only mode), useful
for dashboards or non-blocking jobs.

## Policy file

A policy file is a YAML document with a top-level `rules:` list. ECDAT looks
for `ecdat-policy.yaml` / `ecdat-policy.yml` / `.ecdat-policy.yaml` /
`.ecdat-policy.yml` in the target directory, or takes an explicit
`--policy <path>`.

See `docs/ecdat-policy.example.yaml` for a fully annotated example.

### Rule families

**1. Disallowed or key-size-restricted algorithms**

```yaml
- id: no-weak-rsa
  name: No new RSA < 3072 bits
  algorithm: RSA
  min_key_size: 3072
  severity: CRITICAL

- id: no-md5-prod
  name: No MD5 outside tests
  algorithm: MD5
  exclude_paths: ['**/test/**', '**/tests/**', 'test_*']
  severity: HIGH

- id: no-legacy-ciphers
  name: No RC4 / 3DES / DES
  disallow_algorithms: [RC4, 3DES, DES]
  severity: CRITICAL
```

Optional path controls: `include_paths` (only flag files matching any glob)
and `exclude_paths` (skip files matching any glob).

**2. Internet-exposed assets must be PQC-ready**

```yaml
- id: exposed-pqc-ready
  name: Internet-exposed assets must be PQC-ready
  condition: internet_exposed
  require_pqc_ready: true
  deadline: '2030-01-01'
  enforce_immediately: false
  severity: CRITICAL
```

Flagged when an internet-exposed business asset uses a quantum-vulnerable
algorithm. `deadline` + `enforce_immediately: false` defers enforcement
until the deadline passes.

**3. Minimum crypto-agility score**

```yaml
- id: agility-floor
  name: Agility score >= 70
  min_agility_score: 70
  severity: MEDIUM
```

**4. Maximum risk score**

```yaml
- id: risk-ceiling
  name: No asset above risk score 60
  max_risk_score: 60
  severity: HIGH
```

## Copy-paste CI snippet (GitHub Actions)

```yaml
# .github/workflows/ecdat.yml
name: ECDAT cryptographic policy gate
on:
  pull_request:
jobs:
  policy-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0            # needed for an accurate --since base diff
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -r backend/requirements.txt
      - name: Enforce cryptographic policy
        run: |
          cd backend
          python -m app.cli scan . --since origin/main \
            --policy ../ecdat-policy.yaml --json
        env:
          DATABASE_URL: sqlite:////tmp/ecdat_ci.db
```

## Notes

- The example policy file itself is excluded from source scanning
  (`SCAN_EXCLUDED_FILES` in `app/core/config.py`), so a repo policy never
  flags itself.
- If `git diff` fails for any reason (no repo, bad ref) the scan logs a
  warning and falls back to a full scan rather than aborting.