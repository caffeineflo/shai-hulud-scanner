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
