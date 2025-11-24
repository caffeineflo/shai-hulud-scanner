const assert = require('assert');
const { checkInfections } = require('../lib/check-infections');

function testDetectsSHA1HULUDRunner() {
  const runners = [
    { name: 'normal-runner' },
    { name: 'SHA1HULUD' }
  ];

  const findings = checkInfections(runners, [], '');

  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].type, 'runner');
  assert.strictEqual(findings[0].name, 'SHA1HULUD');
}

function testDetectsMaliciousWorkflow() {
  const workflows = [
    { name: 'ci.yml' },
    { name: 'formatter_123456789.yml' }
  ];

  const findings = checkInfections([], workflows, '');

  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].type, 'workflow');
  assert.strictEqual(findings[0].file, 'formatter_123456789.yml');
}

function testDetectsSuspiciousDescription() {
  const findings = checkInfections([], [], 'Sha1-Hulud: The Second Coming.');

  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].type, 'description');
}

function testNoFalsePositives() {
  const findings = checkInfections(
    [{ name: 'normal-runner' }],
    [{ name: 'ci.yml' }],
    'A normal repository'
  );

  assert.strictEqual(findings.length, 0);
}

function runTests() {
  try {
    testDetectsSHA1HULUDRunner();
    testDetectsMaliciousWorkflow();
    testDetectsSuspiciousDescription();
    testNoFalsePositives();
    console.log('✓ All check-infections tests passed');
  } catch (err) {
    console.error('✗ Test failed:', err.message);
    process.exit(1);
  }
}

runTests();
