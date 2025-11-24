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

    # Fetch lock files
    PACKAGE_LOCK=$(gh api "/repos/$FULL_NAME/contents/package-lock.json" \
        --jq '.content' 2>/dev/null | base64 -d 2>/dev/null || echo "")

    YARN_LOCK=$(gh api "/repos/$FULL_NAME/contents/yarn.lock" \
        --jq '.content' 2>/dev/null | base64 -d 2>/dev/null || echo "")

    PNPM_LOCK=$(gh api "/repos/$FULL_NAME/contents/pnpm-lock.yaml" \
        --jq '.content' 2>/dev/null | base64 -d 2>/dev/null || echo "")

    # Check dependencies with lock files
    DEP_FINDINGS=$(node -e "
        const { checkDependencies } = require('./lib/check-dependencies');
        const fs = require('fs');
        const malicious = JSON.parse(fs.readFileSync('shai_hulud_packages.json', 'utf8'));
        const packageJson = \`$PACKAGE_JSON\`;

        const lockFiles = [];
        const packageLock = \`$PACKAGE_LOCK\`;
        const yarnLock = \`$YARN_LOCK\`;
        const pnpmLock = \`$PNPM_LOCK\`;

        if (packageLock) lockFiles.push({ type: 'package-lock.json', content: packageLock });
        if (yarnLock) lockFiles.push({ type: 'yarn.lock', content: yarnLock });
        if (pnpmLock) lockFiles.push({ type: 'pnpm-lock.yaml', content: pnpmLock });

        const findings = checkDependencies(packageJson, lockFiles.length > 0 ? lockFiles : null, malicious);
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
        const description = \`$DESCRIPTION\`;
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
