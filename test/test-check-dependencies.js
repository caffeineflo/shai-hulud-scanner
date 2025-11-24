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

  const result = checkDependencies(packageJson, null, maliciousPackages);

  assert.strictEqual(result.vulnerabilities.length, 2, 'Should detect 2 malicious packages');
  assert.strictEqual(result.vulnerabilities[0].package, 'posthog-node');
  assert.strictEqual(result.vulnerabilities[0].match_type, 'direct');
  assert.strictEqual(result.vulnerabilities[1].package, '@asyncapi/specs');
  assert.strictEqual(result.vulnerabilities[1].match_type, 'direct');
}

function testNoFalsePositives() {
  const packageJson = JSON.stringify({
    dependencies: { 'safe-package': '^1.0.0' }
  });

  const maliciousPackages = [
    { package: 'posthog-node', version: '5.11.3' }
  ];

  const result = checkDependencies(packageJson, null, maliciousPackages);

  assert.strictEqual(result.vulnerabilities.length, 0, 'Should not flag safe packages');
  assert.strictEqual(result.affectedPackages.length, 0, 'Should not flag unrelated packages');
}

function testTracksAffectedPackages() {
  const packageJson = JSON.stringify({
    dependencies: { 'posthog-node': '^6.0.0' }  // Safe version, but affected package
  });

  const maliciousPackages = [
    { package: 'posthog-node', version: '5.11.3' },
    { package: 'posthog-node', version: '5.13.3' }
  ];

  const result = checkDependencies(packageJson, null, maliciousPackages);

  assert.strictEqual(result.vulnerabilities.length, 0, 'Should not flag as vulnerability');
  assert.strictEqual(result.affectedPackages.length, 1, 'Should track affected package');
  assert.strictEqual(result.affectedPackages[0].package, 'posthog-node');
  assert.strictEqual(result.affectedPackages[0].declared_version, '^6.0.0');
  assert.deepStrictEqual(result.affectedPackages[0].malicious_versions, ['5.11.3', '5.13.3']);
}

function testPackageLockDetection() {
  const packageJson = JSON.stringify({
    dependencies: { 'posthog-node': '^5.0.0' }
  });

  const packageLock = fs.readFileSync(
    path.join(__dirname, 'fixtures/package-lock.json'),
    'utf8'
  );

  const maliciousPackages = [
    { package: 'posthog-node', version: '5.11.3' }
  ];

  const lockFiles = [{ type: 'package-lock.json', content: packageLock }];
  const result = checkDependencies(packageJson, lockFiles, maliciousPackages);

  assert.strictEqual(result.vulnerabilities.length, 1, 'Should detect malicious package from lock file');
  assert.strictEqual(result.vulnerabilities[0].package, 'posthog-node');
  assert.strictEqual(result.vulnerabilities[0].malicious_version, '5.11.3');
}

function testYarnLockDetection() {
  const packageJson = JSON.stringify({
    dependencies: { 'posthog-node': '^5.0.0' }
  });

  const yarnLock = fs.readFileSync(
    path.join(__dirname, 'fixtures/yarn.lock'),
    'utf8'
  );

  const maliciousPackages = [
    { package: 'posthog-node', version: '5.11.3' }
  ];

  const lockFiles = [{ type: 'yarn.lock', content: yarnLock }];
  const result = checkDependencies(packageJson, lockFiles, maliciousPackages);

  assert.strictEqual(result.vulnerabilities.length, 1, 'Should detect malicious package from yarn.lock');
  assert.strictEqual(result.vulnerabilities[0].package, 'posthog-node');
}

function testPnpmLockDetection() {
  const packageJson = JSON.stringify({
    dependencies: { 'posthog-node': '^5.0.0' }
  });

  const pnpmLock = fs.readFileSync(
    path.join(__dirname, 'fixtures/pnpm-lock.yaml'),
    'utf8'
  );

  const maliciousPackages = [
    { package: 'posthog-node', version: '5.11.3' }
  ];

  const lockFiles = [{ type: 'pnpm-lock.yaml', content: pnpmLock }];
  const result = checkDependencies(packageJson, lockFiles, maliciousPackages);

  assert.strictEqual(result.vulnerabilities.length, 1, 'Should detect malicious package from pnpm-lock.yaml');
  assert.strictEqual(result.vulnerabilities[0].package, 'posthog-node');
}

function runTests() {
  try {
    testDetectsMaliciousDependency();
    testNoFalsePositives();
    testTracksAffectedPackages();
    testPackageLockDetection();
    testYarnLockDetection();
    testPnpmLockDetection();
    console.log('✓ All check-dependencies tests passed');
  } catch (err) {
    console.error('✗ Test failed:', err.message);
    process.exit(1);
  }
}

runTests();
