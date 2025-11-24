const assert = require('assert');
const { matchesVersion } = require('../lib/semver-match');

function testExactMatch() {
  const result = matchesVersion('5.11.3', '5.11.3');
  assert.strictEqual(result, true, 'Exact version should match');
}

function testRangeMatch() {
  const result = matchesVersion('^5.0.0', '5.11.3');
  assert.strictEqual(result, true, 'Range should match malicious version');
}

function testNoMatch() {
  const result = matchesVersion('^4.0.0', '5.11.3');
  assert.strictEqual(result, false, 'Different major version should not match');
}

function runTests() {
  try {
    testExactMatch();
    testRangeMatch();
    testNoMatch();
    console.log('✓ All semver-match tests passed');
  } catch (err) {
    console.error('✗ Test failed:', err.message);
    process.exit(1);
  }
}

runTests();
