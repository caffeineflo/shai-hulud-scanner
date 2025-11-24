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
