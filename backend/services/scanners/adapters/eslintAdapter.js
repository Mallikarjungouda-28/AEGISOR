const { execSync } = require('child_process');
const { isCommandAvailable } = require('../utils/cliChecker');

const runEslint = async (targetDir) => {
  if (!isCommandAvailable('eslint')) {
    return {
      name: 'ESLint (Code Quality & Security)',
      status: 'unavailable',
      reason: 'ESLint CLI is not installed globally on server environment',
      findings: []
    };
  }

  try {
    const stdout = execSync(
      `eslint "${targetDir}" --format json --no-eslintrc --ext .js,.jsx,.ts,.tsx`,
      {
        timeout: 45000,
        maxBuffer: 5 * 1024 * 1024,
        encoding: 'utf8'
      }
    );

    const data = JSON.parse(stdout || '[]');
    const findings = [];

    for (const file of data) {
      for (const msg of file.messages || []) {
        if (msg.severity >= 2) {
          findings.push({
            title: `Code Quality / Security Issue: ${msg.ruleId || 'Linter Alert'}`,
            description: msg.message,
            severity: 'medium',
            affectedFile: file.filePath,
            lineNumber: msg.line || 1,
            cwe: 'CWE-710',
            detectionSource: 'eslint',
            codeSnippet: null,
            recommendation: `Refactor code to conform to best practices: rule ${msg.ruleId || 'eslint'}`
          });
        }
      }
    }

    return {
      name: 'ESLint (Code Quality & Security)',
      status: 'completed',
      findings
    };
  } catch (error) {
    return {
      name: 'ESLint (Code Quality & Security)',
      status: 'failed',
      reason: error.message,
      findings: []
    };
  }
};

module.exports = { runEslint };

