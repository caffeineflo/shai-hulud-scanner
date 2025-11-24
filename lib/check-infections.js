/**
 * Check for active infection indicators
 * @param {Array} runners - Array of runner objects with {name} property
 * @param {Array} workflows - Array of workflow objects with {name} property
 * @param {string} repoDescription - Repository description
 * @returns {Array} Findings with {type, name/file/evidence, confidence}
 */
function checkInfections(runners, workflows, repoDescription) {
  const findings = [];

  // Check for SHA1HULUD runner
  for (const runner of runners) {
    if (runner.name === 'SHA1HULUD') {
      findings.push({
        type: 'runner',
        name: runner.name,
        confidence: 100
      });
    }
  }

  // Check for malicious workflow files
  for (const workflow of workflows) {
    if (workflow.name === 'formatter_123456789.yml') {
      findings.push({
        type: 'workflow',
        file: workflow.name,
        confidence: 100
      });
    }
  }

  // Check repository description
  if (repoDescription && repoDescription.includes('Sha1-Hulud: The Second Coming')) {
    findings.push({
      type: 'description',
      evidence: repoDescription,
      confidence: 100
    });
  }

  return findings;
}

module.exports = { checkInfections };
