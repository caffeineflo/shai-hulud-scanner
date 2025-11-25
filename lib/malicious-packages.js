/**
 * Load malicious packages data from Wiz research GitHub CSV
 */

const https = require('https');
const { parseMaliciousPackagesCsv } = require('./csv-parser');

const CSV_URL =
  'https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/shai-hulud-2-packages.csv';

/**
 * Fetch content from a URL
 * @param {string} url - URL to fetch
 * @returns {Promise<string>}
 */
function fetchUrl(url) {
  return new Promise((resolve, reject) => {
    https
      .get(url, (res) => {
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode}: Failed to fetch ${url}`));
          return;
        }

        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          resolve(data);
        });
      })
      .on('error', reject);
  });
}

/**
 * Load malicious packages from the Wiz research CSV
 * @returns {Promise<Array<{package: string, version: string}>>}
 */
async function loadMaliciousPackages() {
  const csv = await fetchUrl(CSV_URL);
  return parseMaliciousPackagesCsv(csv);
}

/**
 * Load malicious packages synchronously from a CSV string (for use in bash inline scripts)
 * @param {string} csvContent - CSV content
 * @returns {Array<{package: string, version: string}>}
 */
function loadFromCsvContent(csvContent) {
  return parseMaliciousPackagesCsv(csvContent);
}

module.exports = { loadMaliciousPackages, loadFromCsvContent, CSV_URL };
