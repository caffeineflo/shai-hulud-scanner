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
  const findings = checkDependencies(packageJson, lockFiles, maliciousPackages);

  assert.strictEqual(findings.length, 1, 'Should detect malicious package from lock file');
  assert.strictEqual(findings[0].package, 'posthog-node');
  assert.strictEqual(findings[0].malicious_version, '5.11.3');
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
  const findings = checkDependencies(packageJson, lockFiles, maliciousPackages);

  assert.strictEqual(findings.length, 1, 'Should detect malicious package from yarn.lock');
  assert.strictEqual(findings[0].package, 'posthog-node');
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
  const findings = checkDependencies(packageJson, lockFiles, maliciousPackages);

  assert.strictEqual(findings.length, 1, 'Should detect malicious package from pnpm-lock.yaml');
  assert.strictEqual(findings[0].package, 'posthog-node');
}

function runTests() {
  try {
    testDetectsMaliciousDependency();
    testNoFalsePositives();
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
