const { matchesVersion } = require('./semver-match');

/**
 * Parse package-lock.json to extract exact versions
 */
function parsePackageLockJson(content) {
  const versions = {};
  try {
    const lock = JSON.parse(content);

    // v2+ format has packages object
    if (lock.packages) {
      for (const [path, pkg] of Object.entries(lock.packages)) {
        if (path === '') continue; // Skip root
        const name = path.replace(/^node_modules\//, '');
        if (pkg.version) {
          versions[name] = pkg.version;
        }
      }
    }

    // v1 format has dependencies object
    if (lock.dependencies) {
      for (const [name, pkg] of Object.entries(lock.dependencies)) {
        if (pkg.version) {
          versions[name] = pkg.version;
        }
      }
    }
  } catch (err) {
    // Ignore parse errors for lock files
  }
  return versions;
}

/**
 * Parse yarn.lock to extract exact versions
 */
function parseYarnLock(content) {
  const versions = {};
  try {
    const lines = content.split('\n');
    let currentPackage = null;

    for (const line of lines) {
      // Package definition: "package@^1.0.0", package@^1.0.0:
      if (line.match(/^["\w@]/)) {
        const match = line.match(/^["']?([^"'@,]+)/);
        if (match) {
          currentPackage = match[1];
        }
      }
      // Version line:   version "1.2.3"
      if (line.match(/^\s+version/) && currentPackage) {
        const versionMatch = line.match(/version\s+"([^"]+)"/);
        if (versionMatch) {
          versions[currentPackage] = versionMatch[1];
          currentPackage = null;
        }
      }
    }
  } catch (err) {
    // Ignore parse errors for lock files
  }
  return versions;
}

/**
 * Parse pnpm-lock.yaml to extract exact versions
 */
function parsePnpmLock(content) {
  const versions = {};
  try {
    const lines = content.split('\n');

    for (const line of lines) {
      // Look for entries like:   /@babel/code-frame@7.24.1:
      //                            /package-name@version:
      const match = line.match(/^\s+\/([^:]+)@([0-9][^:]*?):/);
      if (match) {
        const [, name, version] = match;
        versions[name] = version;
      }
    }
  } catch (err) {
    // Ignore parse errors for lock files
  }
  return versions;
}

/**
 * Check package.json and lock files for malicious dependencies
 * @param {string} packageJsonContent - Contents of package.json
 * @param {Object|null} lockFiles - Object with {type, content} for each lock file
 * @param {Array} maliciousPackages - Array of {package, version} objects
 * @returns {Array} Findings with {package, declared_version, malicious_version, match_type, severity}
 */
function checkDependencies(packageJsonContent, lockFiles, maliciousPackages) {
  const findings = [];
  const foundPackages = new Set(); // Avoid duplicates

  try {
    const pkg = JSON.parse(packageJsonContent);
    const allDeps = {
      ...pkg.dependencies,
      ...pkg.devDependencies
    };

    // Check declared dependencies in package.json
    for (const [depName, depVersion] of Object.entries(allDeps)) {
      const malicious = maliciousPackages.filter(m => m.package === depName);

      for (const mal of malicious) {
        if (matchesVersion(depVersion, mal.version)) {
          const key = `${depName}@${mal.version}`;
          if (!foundPackages.has(key)) {
            findings.push({
              package: depName,
              declared_version: depVersion,
              malicious_version: mal.version,
              match_type: 'direct',
              severity: 'high'
            });
            foundPackages.add(key);
          }
        }
      }
    }

    // Check lock files for exact versions (including transitive)
    if (lockFiles) {
      let lockedVersions = {};

      for (const lockFile of lockFiles) {
        if (lockFile.type === 'package-lock.json') {
          lockedVersions = { ...lockedVersions, ...parsePackageLockJson(lockFile.content) };
        } else if (lockFile.type === 'yarn.lock') {
          lockedVersions = { ...lockedVersions, ...parseYarnLock(lockFile.content) };
        } else if (lockFile.type === 'pnpm-lock.yaml') {
          lockedVersions = { ...lockedVersions, ...parsePnpmLock(lockFile.content) };
        }
      }

      // Check locked versions against malicious packages
      for (const [depName, lockedVersion] of Object.entries(lockedVersions)) {
        const malicious = maliciousPackages.filter(
          m => m.package === depName && m.version === lockedVersion
        );

        for (const mal of malicious) {
          const key = `${depName}@${mal.version}`;
          if (!foundPackages.has(key)) {
            const isDirect = allDeps.hasOwnProperty(depName);
            findings.push({
              package: depName,
              declared_version: lockedVersion,
              malicious_version: mal.version,
              match_type: isDirect ? 'direct' : 'transitive',
              severity: isDirect ? 'high' : 'medium'
            });
            foundPackages.add(key);
          }
        }
      }
    }
  } catch (err) {
    throw new Error(`Failed to parse package.json: ${err.message}`);
  }

  return findings;
}

module.exports = { checkDependencies };
