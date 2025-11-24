const { execSync } = require('child_process');

const tests = [
  'test/test-semver-match.js',
  'test/test-check-dependencies.js',
  'test/test-check-infections.js'
];

let failed = false;

console.log('Running all tests...\n');

for (const test of tests) {
  try {
    execSync(`node ${test}`, { stdio: 'inherit' });
  } catch (err) {
    failed = true;
  }
}

if (failed) {
  console.error('\n❌ Some tests failed');
  process.exit(1);
} else {
  console.log('\n✅ All tests passed');
}
