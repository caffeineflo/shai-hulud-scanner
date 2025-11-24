#!/usr/bin/env bash

# Shai-Hulud NPM Malware Scanner
# Scans GitHub organization repositories for malicious dependencies and infection indicators

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
    echo "ERROR: Node dependencies not installed. Run: pnpm install"
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
    "potentially_at_risk": [],
    "has_affected_packages": []
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

    # Get git tree recursively to find all npm-related files
    TREE_RESULT=$(gh api "/repos/$FULL_NAME/git/trees/$DEFAULT_BRANCH?recursive=1" 2>/dev/null || echo "")

    if [ -z "$TREE_RESULT" ]; then
        echo "  → Could not fetch repository tree"
        SCANNED=$((SCANNED + 1))
        continue
    fi

    # Check if tree was truncated
    TRUNCATED=$(echo "$TREE_RESULT" | jq -r '.truncated // false')
    if [ "$TRUNCATED" = "true" ]; then
        echo "  ⚠️  WARNING: Repository tree truncated (too many files)"
    fi

    # Find all package.json paths
    PACKAGE_PATHS=$(echo "$TREE_RESULT" | jq -r '.tree[]? | select(.path | endswith("package.json")) | .path')

    # Also check for lock files (to detect repos with lock files but no package.json)
    LOCK_FILES_FOUND=$(echo "$TREE_RESULT" | jq -r '.tree[]? | select(.path | test("package-lock\\.json$|yarn\\.lock$|pnpm-lock\\.yaml$")) | .path')

    if [ -z "$PACKAGE_PATHS" ]; then
        if [ -n "$LOCK_FILES_FOUND" ]; then
            # Found lock files but no package.json - this is unusual
            echo "  ⚠️  WARNING: Found lock files without package.json:"
            echo "$LOCK_FILES_FOUND" | while read -r lock_file; do
                echo "      - $lock_file"
            done
            echo "  → Cannot scan without package.json (orphaned lock files)"
        else
            echo "  → No Node.js packages found (searched for package.json and all lock file types)"
        fi
        SCANNED=$((SCANNED + 1))
        continue
    fi

    # Count packages found
    PACKAGE_COUNT=$(echo "$PACKAGE_PATHS" | wc -l | tr -d ' ')
    if [ "$PACKAGE_COUNT" -gt 1 ]; then
        echo "  → Found $PACKAGE_COUNT packages (monorepo)"
    fi

    # Create temp files for aggregating results across packages
    TMP_VULNS="/tmp/scan-vulns-$$.json"
    TMP_AFFECTED="/tmp/scan-affected-$$.json"
    TMP_WARNINGS="/tmp/scan-warnings-$$.json"
    echo "[]" > "$TMP_VULNS"
    echo "[]" > "$TMP_AFFECTED"
    echo "[]" > "$TMP_WARNINGS"

    # Process each package.json
    while IFS= read -r PKG_PATH; do
        # Extract directory
        PKG_DIR=$(dirname "$PKG_PATH")

        if [ "$PACKAGE_COUNT" -gt 1 ]; then
            echo "    Checking: $PKG_PATH"
        fi

        # Fetch package.json
        FETCH_ERROR=""
        PACKAGE_JSON=$(gh api "/repos/$FULL_NAME/contents/$PKG_PATH" \
            --jq '.content' 2>&1 | base64 -d 2>&1)

        if [ $? -ne 0 ] || [ -z "$PACKAGE_JSON" ]; then
            FETCH_ERROR="Failed to fetch $PKG_PATH"
            echo "      ⚠️  WARNING: $FETCH_ERROR"
            jq --arg path "$PKG_PATH" --arg err "$FETCH_ERROR" \
                '. += [{path: $path, error: $err}]' "$TMP_WARNINGS" > "$TMP_WARNINGS.tmp" && \
                mv "$TMP_WARNINGS.tmp" "$TMP_WARNINGS"
            continue
        fi

        # Look for lock files in the same directory
        LOCK_FILE_NAMES=("package-lock.json" "yarn.lock" "pnpm-lock.yaml")
        LOCK_FILES_JSON="[]"

        for LOCK_NAME in "${LOCK_FILE_NAMES[@]}"; do
            if [ "$PKG_DIR" = "." ]; then
                LOCK_PATH="$LOCK_NAME"
            else
                LOCK_PATH="$PKG_DIR/$LOCK_NAME"
            fi

            # Check if lock file exists in tree
            LOCK_EXISTS=$(echo "$TREE_RESULT" | jq --arg path "$LOCK_PATH" \
                '.tree[]? | select(.path == $path) | .path')

            if [ -n "$LOCK_EXISTS" ]; then
                # Fetch lock file
                LOCK_CONTENT=$(gh api "/repos/$FULL_NAME/contents/$LOCK_PATH" \
                    --jq '.content' 2>&1 | base64 -d 2>&1)

                if [ $? -eq 0 ] && [ -n "$LOCK_CONTENT" ]; then
                    # Successfully fetched lock file
                    if [ "$PACKAGE_COUNT" -gt 1 ]; then
                        echo "      ✓ Found $LOCK_NAME"
                    fi
                    # Add to lock files array
                    TMP_LOCK="/tmp/scan-lock-$$-$(echo "$LOCK_NAME" | tr '.' '-')"
                    echo "$LOCK_CONTENT" > "$TMP_LOCK"
                    LOCK_FILES_JSON=$(echo "$LOCK_FILES_JSON" | jq --arg type "$LOCK_NAME" --arg path "$TMP_LOCK" \
                        '. += [{type: $type, tempPath: $path}]')
                else
                    # Failed to fetch lock file
                    FETCH_ERROR="Failed to fetch $LOCK_PATH (may be >1MB)"
                    echo "      ⚠️  WARNING: $FETCH_ERROR"
                    jq --arg path "$LOCK_PATH" --arg err "$FETCH_ERROR" \
                        '. += [{path: $path, error: $err}]' "$TMP_WARNINGS" > "$TMP_WARNINGS.tmp" && \
                        mv "$TMP_WARNINGS.tmp" "$TMP_WARNINGS"
                fi
            fi
        done

        # Write package.json to temp file
        TMP_PKG="/tmp/scan-pkg-$$.json"
        echo "$PACKAGE_JSON" > "$TMP_PKG"

        # Check dependencies
        DEP_RESULT=$(node -e "
            const { checkDependencies } = require('./lib/check-dependencies');
            const fs = require('fs');
            const malicious = JSON.parse(fs.readFileSync('shai_hulud_packages.json', 'utf8'));
            const packageJson = fs.readFileSync('$TMP_PKG', 'utf8');

            const lockFilesData = $LOCK_FILES_JSON;
            const lockFiles = [];

            for (const lockFile of lockFilesData) {
                const content = fs.readFileSync(lockFile.tempPath, 'utf8');
                if (content.trim()) {
                    lockFiles.push({ type: lockFile.type, content: content });
                }
            }

            const result = checkDependencies(packageJson, lockFiles.length > 0 ? lockFiles : null, malicious);
            console.log(JSON.stringify(result));
        " 2>/dev/null || echo '{"vulnerabilities":[],"affectedPackages":[]}')

        # Cleanup temp files
        rm -f "$TMP_PKG"
        echo "$LOCK_FILES_JSON" | jq -r '.[].tempPath' | xargs -I {} rm -f {}

        # Merge results - add package path to each finding
        PKG_VULNERABILITIES=$(echo "$DEP_RESULT" | jq --arg path "$PKG_PATH" \
            '.vulnerabilities | map(. + {package_json_path: $path})')
        PKG_AFFECTED=$(echo "$DEP_RESULT" | jq --arg path "$PKG_PATH" \
            '.affectedPackages | map(. + {package_json_path: $path})')

        # Append to temp files
        jq --argjson new "$PKG_VULNERABILITIES" '. + $new' "$TMP_VULNS" > "$TMP_VULNS.tmp" && \
            mv "$TMP_VULNS.tmp" "$TMP_VULNS"
        jq --argjson new "$PKG_AFFECTED" '. + $new' "$TMP_AFFECTED" > "$TMP_AFFECTED.tmp" && \
            mv "$TMP_AFFECTED.tmp" "$TMP_AFFECTED"
    done < <(echo "$PACKAGE_PATHS")

    # Read aggregated results from temp files
    DEP_FINDINGS=$(cat "$TMP_VULNS")
    AFFECTED_PKGS=$(cat "$TMP_AFFECTED")
    SCAN_WARNINGS=$(cat "$TMP_WARNINGS")

    # Cleanup temp files
    rm -f "$TMP_VULNS" "$TMP_AFFECTED" "$TMP_WARNINGS"

    # Check for runners
    RUNNERS=$(gh api "/repos/$FULL_NAME/actions/runners" \
        --jq '.runners' 2>/dev/null || echo "[]")

    # Check for workflows
    WORKFLOWS=$(gh api "/repos/$FULL_NAME/contents/.github/workflows" \
        --jq '.[] | {name: .name}' 2>/dev/null | jq -s '.' || echo "[]")

    # Check infections
    TMP_DESC="/tmp/scan-desc-$$.txt"
    echo "$DESCRIPTION" > "$TMP_DESC"

    INF_FINDINGS=$(node -e "
        const { checkInfections } = require('./lib/check-infections');
        const fs = require('fs');
        const runners = $RUNNERS;
        const workflows = $WORKFLOWS;
        const description = fs.readFileSync('$TMP_DESC', 'utf8');
        const findings = checkInfections(runners, workflows, description);
        console.log(JSON.stringify(findings));
    " 2>/dev/null || echo "[]")

    rm -f "$TMP_DESC"

    # Display warnings if any
    if [ "$(echo "$SCAN_WARNINGS" | jq 'length')" -gt 0 ]; then
        echo "  ⚠️  WARNINGS:"
        echo "$SCAN_WARNINGS" | jq -r '.[] | "      - \(.path): \(.error)"'
    fi

    # Classify and report
    if [ "$(echo "$INF_FINDINGS" | jq 'length')" -gt 0 ]; then
        echo "  ⚠️  CONFIRMED_INFECTED"
        echo "$INF_FINDINGS" | jq -r '.[] | "      - \(.type): \(.name // .file // .evidence)"'

        # Add to results.json
        FINDING=$(jq -n --arg repo "$FULL_NAME" --argjson indicators "$INF_FINDINGS" --argjson warnings "$SCAN_WARNINGS" \
            '{repo: $repo, indicators: $indicators, warnings: $warnings}')
        jq ".findings.confirmed_infected += [$FINDING]" "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && \
            mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"

    elif [ "$(echo "$DEP_FINDINGS" | jq 'length')" -gt 0 ]; then
        echo "  ⚠️  LIKELY_VULNERABLE"
        echo "$DEP_FINDINGS" | jq -r '.[] | "      - \(.package)@\(.malicious_version) (in \(.package_json_path // "package.json"))"'

        # Add to results.json
        FINDING=$(jq -n --arg repo "$FULL_NAME" --argjson deps "$DEP_FINDINGS" --argjson warnings "$SCAN_WARNINGS" \
            '{repo: $repo, vulnerabilities: $deps, warnings: $warnings}')
        jq ".findings.likely_vulnerable += [$FINDING]" "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && \
            mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"

    elif [ "$(echo "$AFFECTED_PKGS" | jq 'length')" -gt 0 ]; then
        echo "  ℹ️  HAS_AFFECTED_PACKAGES (safe versions)"
        echo "$AFFECTED_PKGS" | jq -r '.[] | "      - \(.package)@\(.declared_version) (malicious: \(.malicious_versions | join(", "))) (in \(.package_json_path // "package.json"))"'

        # Add to results.json
        FINDING=$(jq -n --arg repo "$FULL_NAME" --argjson pkgs "$AFFECTED_PKGS" --argjson warnings "$SCAN_WARNINGS" \
            '{repo: $repo, packages: $pkgs, warnings: $warnings}')
        jq ".findings.has_affected_packages += [$FINDING]" "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && \
            mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    else
        if [ "$(echo "$SCAN_WARNINGS" | jq 'length')" -gt 0 ]; then
            echo "  ✓ Clean (but has warnings)"
        else
            echo "  ✓ Clean"
        fi
    fi

    SCANNED=$((SCANNED + 1))

    # Update scan metadata
    jq ".scan_metadata.total_repos_scanned = $SCANNED" "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && \
        mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"

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
