const { execSync } = require('child_process');
const { isCommandAvailable } = require('../utils/cliChecker');

const runBandit = async (targetDir) => {
  if (!isCommandAvailable('bandit')) {
    return {
      name: 'Bandit (Python AST Security)',
      status: 'unavailable',
      reason: 'Bandit CLI is not installed on the server environment',
      findings: []
    };
  }

  try {
    const stdout = execSync(
      `bandit -r "${targetDir}" -f json`,
      {
        timeout: 45000,
        maxBuffer: 5 * 1024 * 1024,
        encoding: 'utf8'
      }
    );

    const data = JSON.parse(stdout || '{}');
    const findings = (data.results || []).map((res) => ({
      title: `Python Security Finding: ${res.test_name || res.test_id}`,
      description: res.issue_text,
      severity: res.issue_severity ? res.issue_severity.toLowerCase() : 'medium',
      affectedFile: res.filename,
      lineNumber: res.line_number || 1,
      cwe: `CWE-${res.issue_cwe?.id || 'Unknown'}`,
      detectionSource: 'bandit',
      codeSnippet: res.code,
      recommendation: `Follow Python security best practice: ${res.more_info || 'Sanitize input.'}`
    }));

    return {
      name: 'Bandit (Python AST Security)',
      status: 'completed',
      findings
    };
  } catch (error) {
    return {
      name: 'Bandit (Python AST Security)',
      status: 'failed',
      reason: error.message,
      findings: []
    };
  }
};

module.exports = { runBandit };

