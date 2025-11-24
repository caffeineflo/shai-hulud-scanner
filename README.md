# Shai-Hulud NPM Malware Scanner

Comprehensive scanner to detect Betterment repositories affected by the Shai-Hulud NPM malware attack (November 24, 2025).

## Overview

This scanner detects:
- **Vulnerable dependencies**: Repos depending on 300+ poisoned NPM packages
  - Checks `package.json` for direct dependencies
  - Checks `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml` for exact locked versions (including transitive dependencies)
- **Active infections**: SHA1HULUD runners, malicious workflows, suspicious repo descriptions

## Prerequisites

- [GitHub CLI](https://cli.github.com) (authenticated)
- Node.js 16+
- npm

## Installation

```bash
npm install
```

## Usage

```bash
./scan-shai-hulud.sh
```

The scanner will:
1. Fetch all repositories from the Betterment organization
2. Check each repo for malicious dependencies and infection indicators
3. Output live results to console
4. Save detailed findings to `results.json`

### Resuming Scans

If interrupted, the scanner saves progress to `.scan-cache.json`. On restart, it will prompt to resume from the last checkpoint.

### Environment Variables

- `ORG_NAME`: GitHub organization to scan (default: `Betterment`)

Example:
```bash
ORG_NAME=MyOrg ./scan-shai-hulud.sh
```

## Output

### Console Output

```
[1/150] Scanning: betterment/example-repo
  ⚠️  CONFIRMED_INFECTED
      - runner: SHA1HULUD
      - workflow: formatter_123456789.yml

[2/150] Scanning: betterment/another-repo
  ⚠️  LIKELY_VULNERABLE
      - posthog-node@5.11.3

[3/150] Scanning: betterment/clean-repo
  ✓ Clean
```

### JSON Output (`results.json`)

```json
{
  "scan_metadata": {
    "scan_date": "2025-11-24T...",
    "org": "Betterment",
    "total_repos_scanned": 150,
    "repos_with_npm": 87
  },
  "findings": {
    "confirmed_infected": [...],
    "likely_vulnerable": [...],
    "potentially_at_risk": [...]
  },
  "errors": [...]
}
```

## Testing

```bash
npm test
```

## Architecture

See [Design Document](docs/plans/2025-11-24-shai-hulud-scanner-design.md) for detailed architecture and implementation notes.

### Components

- `scan-shai-hulud.sh`: Main bash orchestrator using gh CLI
- `lib/check-dependencies.js`: Dependency matching with semver (supports npm, yarn, and pnpm lock files)
- `lib/check-infections.js`: Infection indicator detection
- `lib/semver-match.js`: Version range matching utility

### Lock File Support

The scanner automatically detects and parses:
- **package-lock.json** (npm v1 and v2+ formats)
- **yarn.lock** (Yarn Classic and Berry)
- **pnpm-lock.yaml** (pnpm)

Lock files enable detection of malicious transitive dependencies (dependencies-of-dependencies) with exact version matching.

## Rate Limits

The scanner uses authenticated GitHub API calls (5,000 requests/hour). For 150 repos with 3-5 API calls each, expect:
- Total requests: ~600
- Scan time: 10-15 minutes

## Security Note

This scanner is read-only and makes no modifications to repositories. It only fetches metadata and file contents for analysis.

## References

- [Shai-Hulud Attack Analysis](https://helixguard.io/blog/shai-hulud-returns)
- [Malicious Packages List](shai_hulud_packages.json)
