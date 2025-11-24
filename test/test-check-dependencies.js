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
