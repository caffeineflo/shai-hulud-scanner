/**
 * Parse CSV containing malicious packages from Wiz research
 * Format: Package,Version where Version is "= X.Y.Z" or "= X.Y.Z || = A.B.C"
 */

/**
 * Parse the malicious packages CSV and return array of {package, version} objects
 * @param {string} csvContent - Raw CSV content
 * @returns {Array<{package: string, version: string}>}
 */
function parseMaliciousPackagesCsv(csvContent) {
  const packages = [];

  // Normalize line endings and split
  const lines = csvContent.replace(/\r\n/g, '\n').split('\n');

  // Skip header row
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    // Split on first comma (package names can contain commas in theory, but not in practice)
    const commaIndex = line.indexOf(',');
    if (commaIndex === -1) continue;

    const packageName = line.slice(0, commaIndex).trim();
    const versionSpec = line.slice(commaIndex + 1).trim();

    if (!packageName || !versionSpec) continue;

    // Handle multiple versions separated by ||
    const versionParts = versionSpec.split('||');

    for (const part of versionParts) {
      // Strip "= " prefix and trim
      const version = part.trim().replace(/^=\s*/, '');
      if (version) {
        packages.push({ package: packageName, version });
      }
    }
  }

  return packages;
}

module.exports = { parseMaliciousPackagesCsv };
