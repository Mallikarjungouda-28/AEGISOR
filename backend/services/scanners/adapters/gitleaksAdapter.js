const { execSync } = require('child_process');
const { isCommandAvailable } = require('../utils/cliChecker');

const runGitleaks = async (targetDir) => {
  if (!isCommandAvailable('gitleaks')) {
    return {
      name: 'Gitleaks (Secret Detection)',
      status: 'unavailable',
      reason: 'Gitleaks CLI is not installed on the server environment',
      findings: []
    };
  }

  try {
    const stdout = execSync(
      `gitleaks dir "${targetDir}" --no-git --report-format json`,
      {
        timeout: 45000,
        maxBuffer: 5 * 1024 * 1024,
        encoding: 'utf8'
      }
    );

    const data = JSON.parse(stdout || '[]');
    const findings = data.map((leak) => ({
      title: `Exposed Credential: ${leak.Description || 'Hardcoded Secret'}`,
      description: `Potential hardcoded secret or credential detected in source code.`,
      severity: 'critical',
      affectedFile: leak.File,
      lineNumber: leak.StartLine || 1,
      cwe: 'CWE-798',
      detectionSource: 'gitleaks',
      codeSnippet: `Match: ${leak.Match ? leak.Match.substring(0, 8) + '...' : 'REDACTED'}`,
      recommendation: 'Immediately revoke this credential and migrate to environment variables or a secrets manager.'
    }));

    return {
      name: 'Gitleaks (Secret Detection)',
      status: 'completed',
      findings
    };
  } catch (error) {
    return {
      name: 'Gitleaks (Secret Detection)',
      status: 'failed',
      reason: error.message,
      findings: []
    };
  }
};

module.exports = { runGitleaks };

