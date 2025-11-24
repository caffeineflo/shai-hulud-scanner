# Shai-Hulud NPM Malware Scanner Design

**Date:** 2025-11-24
**Status:** Design Complete
**Purpose:** Comprehensive scanner to detect Betterment repositories affected by the Shai-Hulud NPM malware attack

## Background

On November 24, 2025, over 300 NPM packages were poisoned with malware that:
- Downloads and runs TruffleHog to steal credentials (NPM tokens, AWS/GCP/Azure credentials)
- Creates GitHub Action runners named "SHA1HULUD"
- Exfiltrates data via malicious workflows (`formatter_123456789.yml`)
- Sets repository description to "Sha1-Hulud: The Second Coming."
- Propagates worm-like by republishing infected packages

This scanner will identify Betterment repositories that are either:
1. **Vulnerable**: Depend on malicious package versions
2. **Infected**: Show active indicators of compromise

## Requirements

### Scope
- **Repository Coverage**: All Betterment organization repositories
- **Detection Types**:
  - Dependency scanning (package.json/lock files)
  - Active infection indicators (runners, workflows, descriptions)
- **Output Format**: Console summary + JSON file for programmatic access
- **Package List**: Hardcoded from `shai_hulud_packages.json` (300+ malicious packages)

### Constraints
- Use `gh api` for all GitHub interactions (handles auth and rate limits)
- No special performance requirements (standard approach)
- Must handle interruptions gracefully

## Architecture

### High-Level Design

**Approach**: Async stream processing
- Repos fetched via paginated GitHub API
- Each repo processed as it arrives (async iteration)
- Results accumulated and checkpointed periodically
- Memory efficient, natural rate limit handling

**Components**:
```
scan-shai-hulud.sh          # Main bash orchestrator
lib/
  check-dependencies.js     # Dependency matching with semver
  check-infections.js       # Infection indicator detection
  semver-match.js          # Version range matching helper
shai_hulud_packages.json    # Malicious package list (exists)
.scan-cache.json            # Progress checkpoint (gitignored)
```

### Data Flow

**1. Repository Discovery**
```bash
gh api /orgs/Betterment/repos --paginate --jq '.[]|{name,full_name,default_branch}'
```
- Streams all repos from Betterment organization
- Paginated automatically by gh CLI

**2. Dependency Checking (per repo)**
```bash
# Fetch package.json
gh api /repos/Betterment/{repo}/contents/package.json

# Fetch lock files if they exist
gh api /repos/Betterment/{repo}/contents/package-lock.json
gh api /repos/Betterment/{repo}/contents/yarn.lock
gh api /repos/Betterment/{repo}/contents/pnpm-lock.yaml
```
- Parse dependencies and devDependencies
- Match against malicious package list (name + version)
- Use semver to check if vulnerable versions fall within declared ranges
  - Example: `posthog-node: ^5.0.0` matches malicious version `5.11.3`

**3. Infection Indicator Checks (per repo)**

Three concurrent checks:

a) **SHA1HULUD Runners**
```bash
gh api /repos/Betterment/{repo}/actions/runners
```
Look for runners named "SHA1HULUD"

b) **Malicious Workflows**
```bash
gh api /repos/Betterment/{repo}/contents/.github/workflows
```
Look for:
- File named `formatter_123456789.yml`
- Workflows downloading actions-runner
- Workflows creating `actionsSecrets.json`

c) **Repository Description**
Check repo metadata for "Sha1-Hulud: The Second Coming."

**4. Result Aggregation**
- Stream findings to console (live updates)
- Accumulate in memory for final JSON output
- Checkpoint to `.scan-cache.json` every 50 repos

## Detection Logic

### Confidence Scoring

Each indicator gets a weight:

| Indicator | Weight | Classification |
|-----------|--------|----------------|
| SHA1HULUD runner found | 100% | CONFIRMED_INFECTED |
| Malicious workflow file | 100% | CONFIRMED_INFECTED |
| Suspicious repo description | 100% | CONFIRMED_INFECTED |
| Direct malicious dependency | 75% | LIKELY_VULNERABLE |
| Transitive malicious dependency | 50% | POTENTIALLY_AT_RISK |

**Classification Rules:**
- Any infection indicator → CONFIRMED_INFECTED
- Direct dependency match → LIKELY_VULNERABLE
- Transitive dependency match → POTENTIALLY_AT_RISK

### Version Matching

For each dependency in package.json/lock files:
1. Extract package name and version/range
2. Look up package in `shai_hulud_packages.json`
3. Use semver matching:
   - Exact match: `5.11.3` matches malicious `5.11.3`
   - Range match: `^5.0.0` matches malicious `5.11.3`
   - Lock file match: Exact version from lock file

## Error Handling

### Repository Access Issues
- **Private repos without package.json**: Skip dependency check, still check infection indicators
- **404 on package.json**: Log as "no npm dependencies", continue
- **Empty repos**: Mark as "skipped", move to next

### API Errors
- **Rate limit exceeded**: `gh api` pauses/retries automatically
- **Network failures**: Catch and log, continue with remaining repos
- **Malformed JSON**: Catch parse errors, log repo name, continue

### Dependency Parsing
- **Invalid package.json**: Log error with repo name, mark as "parse_failed"
- **Missing lock files**: Only check package.json (less precise but still useful)
- **Version range edge cases**: Log ambiguous matches for manual review

### Progress Tracking

**Checkpoint Strategy:**
- Write `.scan-cache.json` every 50 repos
- Include: last processed repo name, partial results, timestamp
- On restart: Check for cache, prompt user to resume or start fresh

**Cache Format:**
```json
{
  "last_processed_repo": "betterment/example-repo",
  "repos_processed": 50,
  "timestamp": "2025-11-24T10:30:00Z",
  "partial_results": {
    "confirmed_infected": [...],
    "likely_vulnerable": [...],
    "potentially_at_risk": [...]
  }
}
```

## Output Format

### Console Output
- Progress bar showing repos scanned
- Live findings as they're discovered:
  ```
  [CONFIRMED_INFECTED] betterment/example-repo
    - SHA1HULUD runner detected
    - Malicious workflow: formatter_123456789.yml

  [LIKELY_VULNERABLE] betterment/another-repo
    - Direct dependency: posthog-node@5.11.3
  ```

### JSON Output (`results.json`)
```json
{
  "scan_metadata": {
    "scan_date": "2025-11-24T...",
    "total_repos_scanned": 150,
    "repos_with_npm": 87,
    "scan_duration_seconds": 245
  },
  "findings": {
    "confirmed_infected": [
      {
        "repo": "betterment/example-repo",
        "indicators": [
          {"type": "runner", "name": "SHA1HULUD"},
          {"type": "workflow", "file": "formatter_123456789.yml"}
        ],
        "dependencies": []
      }
    ],
    "likely_vulnerable": [
      {
        "repo": "betterment/another-repo",
        "indicators": [],
        "dependencies": [
          {
            "package": "posthog-node",
            "version": "5.11.3",
            "match_type": "direct",
            "declared_in": "package.json"
          }
        ]
      }
    ],
    "potentially_at_risk": [...]
  },
  "errors": [
    {
      "repo": "betterment/broken-repo",
      "error": "Failed to parse package.json",
      "details": "Unexpected token..."
    }
  ]
}
```

## Implementation Details

### Main Script (scan-shai-hulud.sh)

```bash
#!/bin/bash
set -euo pipefail

# 1. Preflight checks
#    - Verify gh CLI installed and authenticated
#    - Verify node installed
#    - Load shai_hulud_packages.json

# 2. Check for existing cache
#    - If .scan-cache.json exists, prompt to resume

# 3. Fetch repos
#    - gh api /orgs/Betterment/repos --paginate

# 4. Process each repo
#    - Fetch package files (async)
#    - Run dependency check (node lib/check-dependencies.js)
#    - Run infection check (node lib/check-infections.js)
#    - Print findings to console
#    - Accumulate to JSON
#    - Checkpoint every 50 repos

# 5. Write final results.json
```

### Dependency Checker (lib/check-dependencies.js)

**Inputs:**
- package.json content (string)
- Lock file content (string, optional)
- Malicious packages list (array)

**Logic:**
1. Parse package.json for dependencies + devDependencies
2. Parse lock file if present for exact versions
3. For each dependency:
   - Check if package name exists in malicious list
   - Use semver to match version/range against malicious versions
   - Classify as direct or transitive
4. Return findings array

**Output:**
```javascript
[
  {
    package: "posthog-node",
    declared_version: "^5.0.0",
    malicious_version: "5.11.3",
    match_type: "direct",
    severity: "high"
  }
]
```

### Infection Checker (lib/check-infections.js)

**Inputs:**
- Runners list (JSON array)
- Workflows list (JSON array)
- Repo description (string)

**Logic:**
1. Check runners for name === "SHA1HULUD"
2. Check workflows for:
   - File name === "formatter_123456789.yml"
   - Content patterns (actions-runner download, actionsSecrets.json)
3. Check description for "Sha1-Hulud: The Second Coming."

**Output:**
```javascript
[
  {
    type: "runner",
    name: "SHA1HULUD",
    confidence: 100
  },
  {
    type: "workflow",
    file: "formatter_123456789.yml",
    confidence: 100
  }
]
```

## Rate Limiting Considerations

**GitHub API Limits:**
- Authenticated: 5,000 requests/hour
- Unauthenticated: 60 requests/hour

**Estimated Usage:**
- Per repo: 3-5 API calls (package.json, lock file, runners, workflows)
- For 150 repos: ~600 API calls
- Time estimate: ~10-15 minutes with async processing

**Strategy:**
- Use authenticated gh CLI (5,000 req/hr)
- Async processing to maximize throughput
- gh CLI handles retry/backoff automatically

## Success Criteria

The scanner is successful when it:
1. ✅ Scans all Betterment repositories
2. ✅ Detects both vulnerable dependencies and active infections
3. ✅ Produces console summary for quick review
4. ✅ Outputs JSON file for programmatic analysis
5. ✅ Handles errors gracefully without crashing
6. ✅ Can resume from checkpoint if interrupted
7. ✅ Completes within rate limit constraints

## Future Enhancements (Out of Scope)

- Automated remediation (create PRs to update dependencies)
- Continuous monitoring (scheduled scans)
- Integration with security dashboards
- Notification system for new findings
- Historical tracking of scan results
