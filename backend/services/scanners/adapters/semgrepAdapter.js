const { execSync } = require('child_process');
const { isCommandAvailable } = require('../utils/cliChecker');

const runSemgrep = async (targetDir) => {
  if (!isCommandAvailable('semgrep')) {
    return {
      name: 'Semgrep (SAST)',
      status: 'unavailable',
      reason: 'Semgrep CLI is not installed on the server environment',
      findings: []
    };
  }

  try {
    // Run semgrep in restricted JSON mode with strict timeout
    const stdout = execSync(
      `semgrep scan --config auto --json --quiet "${targetDir}"`,
      {
        timeout: 60000,
        maxBuffer: 10 * 1024 * 1024,
        encoding: 'utf8'
      }
    );

    const data = JSON.parse(stdout);
    const findings = (data.results || []).map((item) => ({
      title: item.extra?.message?.split('\n')[0] || item.check_id,
      description: item.extra?.message || 'Static code security finding',
      severity: mapSeverity(item.extra?.severity),
      affectedFile: item.path,
      lineNumber: item.start?.line || 1,
      cwe: item.extra?.metadata?.cwe?.[0] || 'CWE-Unknown',
      detectionSource: 'semgrep',
      codeSnippet: item.extra?.lines || null,
      recommendation: item.extra?.fix || 'Review code logic and apply recommended security pattern.'
    }));

    return {
      name: 'Semgrep (SAST)',
      status: 'completed',
      findings
    };
  } catch (error) {
    return {
      name: 'Semgrep (SAST)',
      status: 'failed',
      reason: error.message,
      findings: []
    };
  }
};

const mapSeverity = (sev) => {
  const s = (sev || '').toUpperCase();
  if (s === 'ERROR') return 'high';
  if (s === 'WARNING') return 'medium';
  if (s === 'INFO') return 'low';
  return 'medium';
};

module.exports = { runSemgrep };

