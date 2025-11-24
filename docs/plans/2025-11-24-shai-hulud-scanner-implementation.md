# Shai-Hulud Scanner Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a comprehensive scanner to detect Betterment repositories affected by Shai-Hulud NPM malware

**Architecture:** Bash orchestrator using gh CLI for GitHub API access, Node.js modules for dependency/infection checking, async stream processing

**Tech Stack:** Bash, Node.js (built-in modules only), gh CLI, semver library

---

## Task 1: Project Setup

**Files:**
- Create: `lib/` directory
- Create: `.gitignore`
- Create: `package.json`

**Step 1: Create lib directory**

```bash
mkdir -p lib
```

**Step 2: Create .gitignore**

Create `.gitignore`:

```gitignore
# Cache files
.scan-cache.json

# Results
results.json

# Node modules
node_modules/

# OS files
.DS_Store
```

**Step 3: Create package.json**

Create `package.json`:

```json
{
  "name": "shai-hulud-scanner",
  "version": "1.0.0",
  "description": "Scanner for Shai-Hulud NPM malware",
  "main": "lib/check-dependencies.js",
  "scripts": {
    "test": "node test/run-tests.js"
  },
  "dependencies": {
    "semver": "^7.6.0"
  },
  "author": "",
  "license": "MIT"
}
```

**Step 4: Install dependencies**

Run: `npm install`
Expected: semver package installed

**Step 5: Commit**

```bash
git add .gitignore package.json package-lock.json
git commit -m "chore: initialize scanner project structure"
```

---

## Task 2: Semver Matching Utility

**Files:**
- Create: `lib/semver-match.js`
- Create: `test/test-semver-match.js`

**Step 1: Write the failing test**

Create `test/test-semver-match.js`:

```javascript
const assert = require('assert');
const { matchesVersion } = require('../lib/semver-match');

function testExactMatch() {
  const result = matchesVersion('5.11.3', '5.11.3');
  assert.strictEqual(result, true, 'Exact version should match');
}

function testRangeMatch() {
  const result = matchesVersion('^5.0.0', '5.11.3');
  assert.strictEqual(result, true, 'Range should match malicious version');
}

function testNoMatch() {
  const result = matchesVersion('^4.0.0', '5.11.3');
  assert.strictEqual(result, false, 'Different major version should not match');
}

function runTests() {
  try {
    testExactMatch();
    testRangeMatch();
    testNoMatch();
    console.log('✓ All semver-match tests passed');
  } catch (err) {
    console.error('✗ Test failed:', err.message);
    process.exit(1);
  }
}

runTests();
```

**Step 2: Run test to verify it fails**

Run: `node test/test-semver-match.js`
Expected: FAIL with "Cannot find module '../lib/semver-match'"

**Step 3: Write minimal implementation**

Create `lib/semver-match.js`:

```javascript
const semver = require('semver');

/**
 * Check if a declared version/range matches a specific malicious version
 * @param {string} declaredVersion - Version or range from package.json (e.g., "^5.0.0", "5.11.3")
 * @param {string} maliciousVersion - Exact malicious version (e.g., "5.11.3")
 * @returns {boolean} True if malicious version satisfies declared version
 */
function matchesVersion(declaredVersion, maliciousVersion) {
  try {
    // Try to parse as a valid semver range
    return semver.satisfies(maliciousVersion, declaredVersion);
  } catch (err) {
    // If parsing fails, try exact string match
    return declaredVersion === maliciousVersion;
  }
}

module.exports = { matchesVersion };
```

**Step 4: Run test to verify it passes**

Run: `node test/test-semver-match.js`
Expected: "✓ All semver-match tests passed"

**Step 5: Commit**

```bash
git add lib/semver-match.js test/test-semver-match.js
git commit -m "feat: add semver version matching utility"
```

---

## Task 3: Dependency Checker

**Files:**
- Create: `lib/check-dependencies.js`
- Create: `test/test-check-dependencies.js`
- Create: `test/fixtures/package.json`

**Step 1: Create test fixtures**

Create `test/fixtures/package.json`:

```json
{
  "name": "test-repo",
  "dependencies": {
    "posthog-node": "^5.0.0",
    "safe-package": "^1.0.0"
  },
  "devDependencies": {
    "@asyncapi/specs": "6.8.2"
  }
}
```

**Step 2: Write the failing test**

Create `test/test-check-dependencies.js`:

```javascript
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { checkDependencies } = require('../lib/check-dependencies');

function testDetectsMaliciousDependency() {
  const packageJson = fs.readFileSync(
    path.join(__dirname, 'fixtures/package.json'),
    'utf8'
  );

  const maliciousPackages = [
    { package: 'posthog-node', version: '5.11.3' },
    { package: '@asyncapi/specs', version: '6.8.2' }
  ];

  const findings = checkDependencies(packageJson, null, maliciousPackages);

  assert.strictEqual(findings.length, 2, 'Should detect 2 malicious packages');
  assert.strictEqual(findings[0].package, 'posthog-node');
  assert.strictEqual(findings[0].match_type, 'direct');
  assert.strictEqual(findings[1].package, '@asyncapi/specs');
  assert.strictEqual(findings[1].match_type, 'direct');
}

function testNoFalsePositives() {
  const packageJson = JSON.stringify({
    dependencies: { 'safe-package': '^1.0.0' }
  });

  const maliciousPackages = [
    { package: 'posthog-node', version: '5.11.3' }
  ];

  const findings = checkDependencies(packageJson, null, maliciousPackages);

  assert.strictEqual(findings.length, 0, 'Should not flag safe packages');
}

function runTests() {
  try {
    testDetectsMaliciousDependency();
    testNoFalsePositives();
    console.log('✓ All check-dependencies tests passed');
  } catch (err) {
    console.error('✗ Test failed:', err.message);
    process.exit(1);
  }
}

runTests();
```

**Step 3: Run test to verify it fails**

Run: `mkdir -p test/fixtures && node test/test-check-dependencies.js`
Expected: FAIL with "Cannot find module '../lib/check-dependencies'"

**Step 4: Write minimal implementation**

Create `lib/check-dependencies.js`:

```javascript
const { matchesVersion } = require('./semver-match');

/**
 * Check package.json for malicious dependencies
 * @param {string} packageJsonContent - Contents of package.json
 * @param {string|null} lockFileContent - Contents of lock file (optional)
 * @param {Array} maliciousPackages - Array of {package, version} objects
 * @returns {Array} Findings with {package, declared_version, malicious_version, match_type, severity}
 */
function checkDependencies(packageJsonContent, lockFileContent, maliciousPackages) {
  const findings = [];

  try {
    const pkg = JSON.parse(packageJsonContent);
    const allDeps = {
      ...pkg.dependencies,
      ...pkg.devDependencies
    };

    // Check each declared dependency
    for (const [depName, depVersion] of Object.entries(allDeps)) {
      // Find matching malicious packages
      const malicious = maliciousPackages.filter(m => m.package === depName);

      for (const mal of malicious) {
        if (matchesVersion(depVersion, mal.version)) {
          findings.push({
            package: depName,
            declared_version: depVersion,
            malicious_version: mal.version,
            match_type: 'direct',
            severity: 'high'
          });
        }
      }
    }
  } catch (err) {
    throw new Error(`Failed to parse package.json: ${err.message}`);
  }

  return findings;
}

module.exports = { checkDependencies };
```

**Step 5: Run test to verify it passes**

Run: `node test/test-check-dependencies.js`
Expected: "✓ All check-dependencies tests passed"

**Step 6: Commit**

```bash
git add lib/check-dependencies.js test/test-check-dependencies.js test/fixtures/
git commit -m "feat: add dependency checker with malicious package detection"
```

---

## Task 4: Infection Checker

**Files:**
- Create: `lib/check-infections.js`
- Create: `test/test-check-infections.js`

**Step 1: Write the failing test**

Create `test/test-check-infections.js`:

```javascript
const assert = require('assert');
const { checkInfections } = require('../lib/check-infections');

function testDetectsSHA1HULUDRunner() {
  const runners = [
    { name: 'normal-runner' },
    { name: 'SHA1HULUD' }
  ];

  const findings = checkInfections(runners, [], '');

  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].type, 'runner');
  assert.strictEqual(findings[0].name, 'SHA1HULUD');
}

function testDetectsMaliciousWorkflow() {
  const workflows = [
    { name: 'ci.yml' },
    { name: 'formatter_123456789.yml' }
  ];

  const findings = checkInfections([], workflows, '');

  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].type, 'workflow');
  assert.strictEqual(findings[0].file, 'formatter_123456789.yml');
}

function testDetectsSuspiciousDescription() {
  const findings = checkInfections([], [], 'Sha1-Hulud: The Second Coming.');

  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].type, 'description');
}

function testNoFalsePositives() {
  const findings = checkInfections(
    [{ name: 'normal-runner' }],
    [{ name: 'ci.yml' }],
    'A normal repository'
  );

  assert.strictEqual(findings.length, 0);
}

function runTests() {
  try {
    testDetectsSHA1HULUDRunner();
    testDetectsMaliciousWorkflow();
    testDetectsSuspiciousDescription();
    testNoFalsePositives();
    console.log('✓ All check-infections tests passed');
  } catch (err) {
    console.error('✗ Test failed:', err.message);
    process.exit(1);
  }
}

runTests();
```

**Step 2: Run test to verify it fails**

Run: `node test/test-check-infections.js`
Expected: FAIL with "Cannot find module '../lib/check-infections'"

**Step 3: Write minimal implementation**

Create `lib/check-infections.js`:

```javascript
/**
 * Check for active infection indicators
 * @param {Array} runners - Array of runner objects with {name} property
 * @param {Array} workflows - Array of workflow objects with {name} property
 * @param {string} repoDescription - Repository description
 * @returns {Array} Findings with {type, name/file/evidence, confidence}
 */
function checkInfections(runners, workflows, repoDescription) {
  const findings = [];

  // Check for SHA1HULUD runner
  for (const runner of runners) {
    if (runner.name === 'SHA1HULUD') {
      findings.push({
        type: 'runner',
        name: runner.name,
        confidence: 100
      });
    }
  }

  // Check for malicious workflow files
  for (const workflow of workflows) {
    if (workflow.name === 'formatter_123456789.yml') {
      findings.push({
        type: 'workflow',
        file: workflow.name,
        confidence: 100
      });
    }
  }

  // Check repository description
  if (repoDescription && repoDescription.includes('Sha1-Hulud: The Second Coming')) {
    findings.push({
      type: 'description',
      evidence: repoDescription,
      confidence: 100
    });
  }

  return findings;
}

module.exports = { checkInfections };
```

**Step 4: Run test to verify it passes**

Run: `node test/test-check-infections.js`
Expected: "✓ All check-infections tests passed"

**Step 5: Commit**

```bash
git add lib/check-infections.js test/test-check-infections.js
git commit -m "feat: add infection indicator detection"
```

---

## Task 5: Main Scanner Script

**Files:**
- Create: `scan-shai-hulud.sh`

**Step 1: Write preflight checks section**

Create `scan-shai-hulud.sh`:

```bash
#!/usr/bin/env bash

# Shai-Hulud NPM Malware Scanner
# Scans Betterment repositories for malicious dependencies and infection indicators

set -o errexit
set -o pipefail
set -o nounset

# === Configuration ===
ORG_NAME="${ORG_NAME:-Betterment}"
CACHE_FILE=".scan-cache.json"
OUTPUT_FILE="results.json"
CHECKPOINT_INTERVAL=50

# === Preflight Checks ===

echo "=== Shai-Hulud Scanner ==="
echo

# Check for gh CLI
if ! command -v gh &> /dev/null; then
    echo "ERROR: gh CLI not found. Install from https://cli.github.com"
    exit 1
fi

# Check gh auth
if ! gh auth status &> /dev/null; then
    echo "ERROR: gh CLI not authenticated. Run: gh auth login"
    exit 1
fi

# Check for node
if ! command -v node &> /dev/null; then
    echo "ERROR: Node.js not found. Install from https://nodejs.org"
    exit 1
fi

# Check for dependencies
if [ ! -d "node_modules" ]; then
    echo "ERROR: Node dependencies not installed. Run: npm install"
    exit 1
fi

# Check for malicious packages list
if [ ! -f "shai_hulud_packages.json" ]; then
    echo "ERROR: shai_hulud_packages.json not found"
    exit 1
fi

echo "✓ All preflight checks passed"
echo
```

**Step 2: Add cache handling**

Add to `scan-shai-hulud.sh`:

```bash
# === Cache Handling ===

RESUME=false
START_FROM_REPO=""

if [ -f "$CACHE_FILE" ]; then
    echo "Found existing scan cache: $CACHE_FILE"
    read -r -p "Resume from last checkpoint? [y/N] " response
    if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        RESUME=true
        START_FROM_REPO=$(jq -r '.last_processed_repo' "$CACHE_FILE")
        echo "Resuming from: $START_FROM_REPO"
    else
        echo "Starting fresh scan"
        rm -f "$CACHE_FILE"
    fi
    echo
fi
```

**Step 3: Add repository fetching**

Add to `scan-shai-hulud.sh`:

```bash
# === Fetch Repositories ===

echo "Fetching repositories from $ORG_NAME..."

# Get all repos
REPOS=$(gh api "/orgs/$ORG_NAME/repos" \
    --paginate \
    --jq '.[] | {name: .name, full_name: .full_name, default_branch: .default_branch, description: .description}' \
    | jq -s '.')

TOTAL_REPOS=$(echo "$REPOS" | jq 'length')
echo "Found $TOTAL_REPOS repositories"
echo

# Initialize results
cat > "$OUTPUT_FILE" <<EOF
{
  "scan_metadata": {
    "scan_date": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "org": "$ORG_NAME",
    "total_repos_scanned": 0,
    "repos_with_npm": 0
  },
  "findings": {
    "confirmed_infected": [],
    "likely_vulnerable": [],
    "potentially_at_risk": []
  },
  "errors": []
}
EOF
```

**Step 4: Add main scan loop**

Add to `scan-shai-hulud.sh`:

```bash
# === Scan Repositories ===

SCANNED=0
SKIP_UNTIL_FOUND=false

if [ "$RESUME" = true ]; then
    SKIP_UNTIL_FOUND=true
fi

echo "Starting scan..."
echo

# Process each repo
echo "$REPOS" | jq -c '.[]' | while read -r repo; do
    REPO_NAME=$(echo "$repo" | jq -r '.name')
    FULL_NAME=$(echo "$repo" | jq -r '.full_name')
    DEFAULT_BRANCH=$(echo "$repo" | jq -r '.default_branch')
    DESCRIPTION=$(echo "$repo" | jq -r '.description // ""')

    # Skip until we reach the resume point
    if [ "$SKIP_UNTIL_FOUND" = true ]; then
        if [ "$FULL_NAME" = "$START_FROM_REPO" ]; then
            SKIP_UNTIL_FOUND=false
            echo "Resuming at: $FULL_NAME"
        else
            continue
        fi
    fi

    echo "[$((SCANNED + 1))/$TOTAL_REPOS] Scanning: $FULL_NAME"

    # Fetch package.json
    PACKAGE_JSON=$(gh api "/repos/$FULL_NAME/contents/package.json" \
        --jq '.content' 2>/dev/null | base64 -d 2>/dev/null || echo "")

    if [ -z "$PACKAGE_JSON" ]; then
        echo "  → No package.json found"
        SCANNED=$((SCANNED + 1))
        continue
    fi

    # Check dependencies
    DEP_FINDINGS=$(node -e "
        const { checkDependencies } = require('./lib/check-dependencies');
        const fs = require('fs');
        const malicious = JSON.parse(fs.readFileSync('shai_hulud_packages.json', 'utf8'));
        const findings = checkDependencies('$PACKAGE_JSON', null, malicious);
        console.log(JSON.stringify(findings));
    " 2>/dev/null || echo "[]")

    # Check for runners
    RUNNERS=$(gh api "/repos/$FULL_NAME/actions/runners" \
        --jq '.runners' 2>/dev/null || echo "[]")

    # Check for workflows
    WORKFLOWS=$(gh api "/repos/$FULL_NAME/contents/.github/workflows" \
        --jq '.[] | {name: .name}' 2>/dev/null | jq -s '.' || echo "[]")

    # Check infections
    INF_FINDINGS=$(node -e "
        const { checkInfections } = require('./lib/check-infections');
        const runners = $RUNNERS;
        const workflows = $WORKFLOWS;
        const description = '$DESCRIPTION';
        const findings = checkInfections(runners, workflows, description);
        console.log(JSON.stringify(findings));
    " 2>/dev/null || echo "[]")

    # Classify and report
    if [ "$(echo "$INF_FINDINGS" | jq 'length')" -gt 0 ]; then
        echo "  ⚠️  CONFIRMED_INFECTED"
        echo "$INF_FINDINGS" | jq -r '.[] | "      - \(.type): \(.name // .file // .evidence)"'
    elif [ "$(echo "$DEP_FINDINGS" | jq 'length')" -gt 0 ]; then
        echo "  ⚠️  LIKELY_VULNERABLE"
        echo "$DEP_FINDINGS" | jq -r '.[] | "      - \(.package)@\(.malicious_version)"'
    else
        echo "  ✓ Clean"
    fi

    SCANNED=$((SCANNED + 1))

    # Checkpoint every N repos
    if [ $((SCANNED % CHECKPOINT_INTERVAL)) -eq 0 ]; then
        echo
        echo "  → Checkpoint: $SCANNED repos scanned"
        cat > "$CACHE_FILE" <<EOF
{
  "last_processed_repo": "$FULL_NAME",
  "repos_processed": $SCANNED,
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF
    fi
done

echo
echo "=== Scan Complete ==="
echo "Total repositories scanned: $SCANNED"
echo "Results saved to: $OUTPUT_FILE"
```

**Step 5: Make script executable**

Run: `chmod +x scan-shai-hulud.sh`

**Step 6: Commit**

```bash
git add scan-shai-hulud.sh
git commit -m "feat: add main scanner script with gh API integration"
```

---

## Task 6: Test Runner

**Files:**
- Create: `test/run-tests.js`

**Step 1: Create test runner**

Create `test/run-tests.js`:

```javascript
const { execSync } = require('child_process');

const tests = [
  'test/test-semver-match.js',
  'test/test-check-dependencies.js',
  'test/test-check-infections.js'
];

let failed = false;

console.log('Running all tests...\n');

for (const test of tests) {
  try {
    execSync(`node ${test}`, { stdio: 'inherit' });
  } catch (err) {
    failed = true;
  }
}

if (failed) {
  console.error('\n❌ Some tests failed');
  process.exit(1);
} else {
  console.log('\n✅ All tests passed');
}
```

**Step 2: Run all tests**

Run: `npm test`
Expected: All tests pass

**Step 3: Commit**

```bash
git add test/run-tests.js
git commit -m "test: add test runner for all unit tests"
```

---

## Task 7: Documentation

**Files:**
- Create: `README.md`

**Step 1: Create README**

Create `README.md`:

```markdown
# Shai-Hulud NPM Malware Scanner

Comprehensive scanner to detect Betterment repositories affected by the Shai-Hulud NPM malware attack (November 24, 2025).

## Overview

This scanner detects:
- **Vulnerable dependencies**: Repos depending on 300+ poisoned NPM packages
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
- `lib/check-dependencies.js`: Dependency matching with semver
- `lib/check-infections.js`: Infection indicator detection
- `lib/semver-match.js`: Version range matching utility

## Rate Limits

The scanner uses authenticated GitHub API calls (5,000 requests/hour). For 150 repos with 3-5 API calls each, expect:
- Total requests: ~600
- Scan time: 10-15 minutes

## Security Note

This scanner is read-only and makes no modifications to repositories. It only fetches metadata and file contents for analysis.

## References

- [Shai-Hulud Attack Analysis](https://helixguard.io/blog/shai-hulud-returns)
- [Malicious Packages List](shai_hulud_packages.json)
```

**Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add comprehensive README with usage instructions"
```

---

## Task 8: Final Integration Test

**Files:**
- Test the complete scanner end-to-end

**Step 1: Run all unit tests**

Run: `npm test`
Expected: All tests pass

**Step 2: Test preflight checks**

Run: `./scan-shai-hulud.sh`
Expected: Script checks for gh, node, dependencies, and malicious packages list

**Step 3: Verify script is ready**

Expected output should show:
```
=== Shai-Hulud Scanner ===

✓ All preflight checks passed

Fetching repositories from Betterment...
```

**Step 4: Commit**

```bash
git add -A
git commit -m "chore: final integration verification"
```

---

## Verification Checklist

Before marking complete, verify:

- [ ] All unit tests pass (`npm test`)
- [ ] Script is executable (`chmod +x scan-shai-hulud.sh`)
- [ ] Preflight checks work (gh, node, dependencies)
- [ ] `.gitignore` excludes cache and results files
- [ ] README documents usage and architecture
- [ ] All commits follow conventional commit format

---

## Notes

**DRY Principles Applied:**
- Reusable semver matching utility
- Modular checker functions
- Shared test infrastructure

**YAGNI Principles Applied:**
- No premature abstractions
- No configuration framework (simple env vars)
- No complex state management (simple JSON cache)

**TDD Applied:**
- Tests written before implementation
- All components have unit tests
- Test runner for continuous verification
