const assert = require('assert');
const { parseMaliciousPackagesCsv } = require('../lib/csv-parser');

// === Basic Parsing ===
function testParsesSimpleCsv() {
  const csv = `Package,Version
02-echo,= 0.0.7
@babel/core,= 7.24.1`;

  const result = parseMaliciousPackagesCsv(csv);

  assert.strictEqual(result.length, 2);
  assert.deepStrictEqual(result[0], { package: '02-echo', version: '0.0.7' });
  assert.deepStrictEqual(result[1], { package: '@babel/core', version: '7.24.1' });
}

function testStripsEqualsSign() {
  const csv = `Package,Version
test-pkg,= 1.2.3`;

  const result = parseMaliciousPackagesCsv(csv);

  assert.strictEqual(result[0].version, '1.2.3', 'Should strip "= " prefix');
}

// === Multiple Versions (OR) ===
function testHandlesOrVersions() {
  const csv = `Package,Version
multi-version-pkg,= 1.0.0 || = 1.0.1 || = 1.0.2`;

  const result = parseMaliciousPackagesCsv(csv);

  assert.strictEqual(result.length, 3, 'Should create entry for each version');
  assert.deepStrictEqual(result[0], { package: 'multi-version-pkg', version: '1.0.0' });
  assert.deepStrictEqual(result[1], { package: 'multi-version-pkg', version: '1.0.1' });
  assert.deepStrictEqual(result[2], { package: 'multi-version-pkg', version: '1.0.2' });
}

// === Edge Cases ===
function testIgnoresEmptyLines() {
  const csv = `Package,Version
pkg1,= 1.0.0

pkg2,= 2.0.0
`;

  const result = parseMaliciousPackagesCsv(csv);

  assert.strictEqual(result.length, 2);
}

function testIgnoresHeaderOnly() {
  const csv = `Package,Version`;

  const result = parseMaliciousPackagesCsv(csv);

  assert.strictEqual(result.length, 0);
}

function testHandlesWindowsLineEndings() {
  const csv = `Package,Version\r\npkg1,= 1.0.0\r\npkg2,= 2.0.0`;

  const result = parseMaliciousPackagesCsv(csv);

  assert.strictEqual(result.length, 2);
  assert.strictEqual(result[0].version, '1.0.0');
  assert.strictEqual(result[1].version, '2.0.0');
}

function testHandlesScopedPackages() {
  const csv = `Package,Version
@scope/package-name,= 1.0.0
@another-scope/pkg,= 2.3.4`;

  const result = parseMaliciousPackagesCsv(csv);

  assert.strictEqual(result.length, 2);
  assert.strictEqual(result[0].package, '@scope/package-name');
  assert.strictEqual(result[1].package, '@another-scope/pkg');
}

function testTrimsWhitespace() {
  const csv = `Package,Version
  spaced-pkg  ,  = 1.0.0  `;

  const result = parseMaliciousPackagesCsv(csv);

  assert.strictEqual(result[0].package, 'spaced-pkg');
  assert.strictEqual(result[0].version, '1.0.0');
}

function runTests() {
  const tests = [
    testParsesSimpleCsv,
    testStripsEqualsSign,
    testHandlesOrVersions,
    testIgnoresEmptyLines,
    testIgnoresHeaderOnly,
    testHandlesWindowsLineEndings,
    testHandlesScopedPackages,
    testTrimsWhitespace,
  ];

  let passed = 0;
  let failed = 0;

  for (const test of tests) {
    try {
      test();
      passed++;
    } catch (err) {
      console.error(`✗ ${test.name}: ${err.message}`);
      failed++;
    }
  }

  console.log(`${passed} passed, ${failed} failed`);

  if (failed > 0) {
    console.log('✗ Some csv-parser tests failed');
    process.exit(1);
  }

  console.log('✓ All csv-parser tests passed');
}

runTests();
