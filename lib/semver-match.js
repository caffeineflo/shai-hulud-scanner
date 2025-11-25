/**
 * Local semver implementation - no external dependencies
 * Implements subset of semver needed for npm version range matching
 */

/**
 * Parse a version string into components
 * @param {string} version - Version string like "5.11.3" or "5.11.3-alpha"
 * @returns {{major: number, minor: number, patch: number, prerelease: string|null}|null}
 */
function parseVersion(version) {
  if (!version || typeof version !== 'string') return null;

  // Match: major.minor.patch with optional prerelease
  const match = version.match(/^(\d+)\.(\d+)\.(\d+)(?:-(.+))?$/);
  if (!match) return null;

  return {
    major: parseInt(match[1], 10),
    minor: parseInt(match[2], 10),
    patch: parseInt(match[3], 10),
    prerelease: match[4] || null,
  };
}

/**
 * Compare two parsed versions
 * @returns {number} -1 if a < b, 0 if equal, 1 if a > b
 */
function compareVersions(a, b) {
  if (a.major !== b.major) return a.major < b.major ? -1 : 1;
  if (a.minor !== b.minor) return a.minor < b.minor ? -1 : 1;
  if (a.patch !== b.patch) return a.patch < b.patch ? -1 : 1;

  // Prerelease versions are less than non-prerelease
  if (a.prerelease && !b.prerelease) return -1;
  if (!a.prerelease && b.prerelease) return 1;

  return 0;
}

/**
 * Check if version satisfies a single comparator (e.g., ">=5.0.0", "<6.0.0")
 */
function satisfiesComparator(version, comparator) {
  comparator = comparator.trim();

  // Handle exact version
  if (/^\d+\.\d+\.\d+/.test(comparator)) {
    const rangeVersion = parseVersion(comparator);
    if (!rangeVersion) return false;
    return compareVersions(version, rangeVersion) === 0;
  }

  // Handle >= operator
  if (comparator.startsWith('>=')) {
    const rangeVersion = parseVersion(comparator.slice(2));
    if (!rangeVersion) return false;
    return compareVersions(version, rangeVersion) >= 0;
  }

  // Handle > operator
  if (comparator.startsWith('>')) {
    const rangeVersion = parseVersion(comparator.slice(1));
    if (!rangeVersion) return false;
    return compareVersions(version, rangeVersion) > 0;
  }

  // Handle <= operator
  if (comparator.startsWith('<=')) {
    const rangeVersion = parseVersion(comparator.slice(2));
    if (!rangeVersion) return false;
    return compareVersions(version, rangeVersion) <= 0;
  }

  // Handle < operator
  if (comparator.startsWith('<')) {
    const rangeVersion = parseVersion(comparator.slice(1));
    if (!rangeVersion) return false;
    return compareVersions(version, rangeVersion) < 0;
  }

  return false;
}

/**
 * Check if version satisfies a semver range
 * @param {string} version - Exact version to check (e.g., "5.11.3")
 * @param {string} range - Semver range (e.g., "^5.0.0", ">=5.0.0 <6.0.0")
 * @returns {boolean}
 */
function satisfies(version, range) {
  const parsedVersion = parseVersion(version);
  if (!parsedVersion) return false;

  range = range.trim();

  // Handle * (any version)
  if (range === '*') {
    // Prerelease doesn't match * by default in semver
    return !parsedVersion.prerelease;
  }

  // Handle X ranges (5.x, 5.11.x)
  const xMatch = range.match(/^(\d+)\.x(?:\.x)?$/);
  if (xMatch) {
    const major = parseInt(xMatch[1], 10);
    return parsedVersion.major === major && !parsedVersion.prerelease;
  }

  const xxMatch = range.match(/^(\d+)\.(\d+)\.x$/);
  if (xxMatch) {
    const major = parseInt(xxMatch[1], 10);
    const minor = parseInt(xxMatch[2], 10);
    return (
      parsedVersion.major === major &&
      parsedVersion.minor === minor &&
      !parsedVersion.prerelease
    );
  }

  // Handle caret range (^)
  if (range.startsWith('^')) {
    const rangeVersion = parseVersion(range.slice(1));
    if (!rangeVersion) return false;

    // Prerelease versions don't match caret ranges by default
    if (parsedVersion.prerelease) return false;

    // ^0.x.y is special: allows changes that do not modify left-most non-zero
    if (rangeVersion.major === 0) {
      if (rangeVersion.minor === 0) {
        // ^0.0.z means exactly 0.0.z
        return compareVersions(parsedVersion, rangeVersion) === 0;
      }
      // ^0.y.z means >=0.y.z <0.(y+1).0
      return (
        parsedVersion.major === 0 &&
        parsedVersion.minor === rangeVersion.minor &&
        parsedVersion.patch >= rangeVersion.patch
      );
    }

    // ^x.y.z means >=x.y.z <(x+1).0.0
    return (
      parsedVersion.major === rangeVersion.major &&
      compareVersions(parsedVersion, rangeVersion) >= 0
    );
  }

  // Handle tilde range (~)
  if (range.startsWith('~')) {
    const rangeVersion = parseVersion(range.slice(1));
    if (!rangeVersion) return false;

    // Prerelease versions don't match tilde ranges by default
    if (parsedVersion.prerelease) return false;

    // ~x.y.z means >=x.y.z <x.(y+1).0
    return (
      parsedVersion.major === rangeVersion.major &&
      parsedVersion.minor === rangeVersion.minor &&
      parsedVersion.patch >= rangeVersion.patch
    );
  }

  // Handle combined ranges (space-separated AND)
  if (range.includes(' ')) {
    const parts = range.split(/\s+/).filter((p) => p);
    return parts.every((part) => satisfiesComparator(parsedVersion, part));
  }

  // Handle single comparators
  return satisfiesComparator(parsedVersion, range);
}

/**
 * Check if a declared version/range matches a specific malicious version
 * @param {string} declaredVersion - Version or range from package.json (e.g., "^5.0.0", "5.11.3")
 * @param {string} maliciousVersion - Exact malicious version (e.g., "5.11.3")
 * @returns {boolean} True if malicious version satisfies declared version
 */
function matchesVersion(declaredVersion, maliciousVersion) {
  return satisfies(maliciousVersion, declaredVersion);
}

module.exports = { matchesVersion, satisfies, parseVersion };
