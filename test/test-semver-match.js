const assert = require('assert');
const { matchesVersion } = require('../lib/semver-match');

// === Exact Match Tests ===
function testExactMatch() {
  assert.strictEqual(matchesVersion('5.11.3', '5.11.3'), true, 'Exact version should match');
}

function testExactMatchDifferent() {
  assert.strictEqual(matchesVersion('5.11.3', '5.11.4'), false, 'Different exact version should not match');
}

// === Caret Range Tests (^) ===
function testCaretRangeMatch() {
  assert.strictEqual(matchesVersion('^5.0.0', '5.11.3'), true, 'Caret range should match higher minor/patch');
}

function testCaretRangeMatchMinor() {
  assert.strictEqual(matchesVersion('^5.2.0', '5.11.3'), true, 'Caret range should match higher minor');
}

function testCaretRangeNoMatchMajor() {
  assert.strictEqual(matchesVersion('^4.0.0', '5.11.3'), false, 'Caret range should not match different major');
}

function testCaretRangeNoMatchLowerMinor() {
  assert.strictEqual(matchesVersion('^5.12.0', '5.11.3'), false, 'Caret range should not match lower minor');
}

function testCaretRangeZeroMajor() {
  // ^0.2.3 means >=0.2.3 <0.3.0 (minor acts like major for 0.x)
  assert.strictEqual(matchesVersion('^0.2.3', '0.2.5'), true, 'Caret 0.x should match same minor');
  assert.strictEqual(matchesVersion('^0.2.3', '0.3.0'), false, 'Caret 0.x should not match different minor');
}

// === Tilde Range Tests (~) ===
function testTildeRangeMatch() {
  assert.strictEqual(matchesVersion('~5.11.0', '5.11.3'), true, 'Tilde range should match higher patch');
}

function testTildeRangeNoMatchMinor() {
  assert.strictEqual(matchesVersion('~5.10.0', '5.11.3'), false, 'Tilde range should not match different minor');
}

function testTildeRangeNoMatchMajor() {
  assert.strictEqual(matchesVersion('~4.11.0', '5.11.3'), false, 'Tilde range should not match different major');
}

// === Comparison Operators ===
function testGreaterThanOrEqual() {
  assert.strictEqual(matchesVersion('>=5.0.0', '5.11.3'), true, 'GTE should match higher version');
  assert.strictEqual(matchesVersion('>=5.11.3', '5.11.3'), true, 'GTE should match equal version');
  assert.strictEqual(matchesVersion('>=6.0.0', '5.11.3'), false, 'GTE should not match lower version');
}

function testLessThan() {
  assert.strictEqual(matchesVersion('<6.0.0', '5.11.3'), true, 'LT should match lower version');
  assert.strictEqual(matchesVersion('<5.11.3', '5.11.3'), false, 'LT should not match equal version');
  assert.strictEqual(matchesVersion('<5.0.0', '5.11.3'), false, 'LT should not match higher version');
}

function testGreaterThan() {
  assert.strictEqual(matchesVersion('>5.0.0', '5.11.3'), true, 'GT should match higher version');
  assert.strictEqual(matchesVersion('>5.11.3', '5.11.3'), false, 'GT should not match equal version');
}

function testLessThanOrEqual() {
  assert.strictEqual(matchesVersion('<=6.0.0', '5.11.3'), true, 'LTE should match lower version');
  assert.strictEqual(matchesVersion('<=5.11.3', '5.11.3'), true, 'LTE should match equal version');
  assert.strictEqual(matchesVersion('<=5.0.0', '5.11.3'), false, 'LTE should not match higher version');
}

// === X-Range Tests ===
function testXRange() {
  assert.strictEqual(matchesVersion('*', '5.11.3'), true, 'Star should match any version');
  assert.strictEqual(matchesVersion('5.x', '5.11.3'), true, 'X range should match same major');
  assert.strictEqual(matchesVersion('5.x', '6.0.0'), false, 'X range should not match different major');
  assert.strictEqual(matchesVersion('5.11.x', '5.11.3'), true, 'X range should match same minor');
  assert.strictEqual(matchesVersion('5.11.x', '5.12.0'), false, 'X range should not match different minor');
}

// === Combined Range Tests ===
function testCombinedRange() {
  assert.strictEqual(matchesVersion('>=5.0.0 <6.0.0', '5.11.3'), true, 'Combined range should match');
  assert.strictEqual(matchesVersion('>=5.0.0 <5.11.0', '5.11.3'), false, 'Combined range should not match outside');
}

// === Edge Cases ===
function testPrerelease() {
  // Prerelease versions are less than non-prerelease
  assert.strictEqual(matchesVersion('^5.11.3', '5.11.3-alpha'), false, 'Prerelease should not match caret range by default');
}

function testInvalidRange() {
  // Invalid ranges should return false (semver can't parse them)
  assert.strictEqual(matchesVersion('latest', '5.11.3'), false, 'Invalid range should not match');
  assert.strictEqual(matchesVersion('latest', 'latest'), false, 'Invalid versions should not match');
}

function runTests() {
  const tests = [
    testExactMatch,
    testExactMatchDifferent,
    testCaretRangeMatch,
    testCaretRangeMatchMinor,
    testCaretRangeNoMatchMajor,
    testCaretRangeNoMatchLowerMinor,
    testCaretRangeZeroMajor,
    testTildeRangeMatch,
    testTildeRangeNoMatchMinor,
    testTildeRangeNoMatchMajor,
    testGreaterThanOrEqual,
    testLessThan,
    testGreaterThan,
    testLessThanOrEqual,
    testXRange,
    testCombinedRange,
    testPrerelease,
    testInvalidRange,
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

  console.log(`\n${passed} passed, ${failed} failed`);

  if (failed > 0) {
    console.log('✗ Some semver-match tests failed');
    process.exit(1);
  }

  console.log('✓ All semver-match tests passed');
}

runTests();
