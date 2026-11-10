const { execSync } = require('child_process');
const { isCommandAvailable } = require('../utils/cliChecker');

const runOsvScanner = async (targetDir) => {
  if (!isCommandAvailable('osv-scanner')) {
    return {
      name: 'OSV-Scanner (SCA / Dependency Audit)',
      status: 'unavailable',
      reason: 'OSV-Scanner CLI is not installed on the server environment',
      findings: []
    };
  }

  try {
    const stdout = execSync(
      `osv-scanner scan --format json --skip-git -r "${targetDir}"`,
      {
        timeout: 60000,
        maxBuffer: 10 * 1024 * 1024,
        encoding: 'utf8'
      }
    );

    const data = JSON.parse(stdout || '{}');
    const findings = [];

    for (const res of data.results || []) {
      for (const pkg of res.packages || []) {
        for (const vuln of pkg.vulnerabilities || []) {
          findings.push({
            title: `Vulnerable Dependency: ${pkg.package?.name}@${pkg.package?.version} (${vuln.id})`,
            description: vuln.details || vuln.summary || 'Known open-source vulnerability.',
            severity: 'high',
            affectedFile: res.source?.path || 'dependency manifest',
            lineNumber: 1,
            cwe: vuln.database_specific?.cwe_ids?.[0] || 'CWE-1395',
            detectionSource: 'osv-scanner',
            codeSnippet: `${pkg.package?.name}@${pkg.package?.version}`,
            recommendation: `Upgrade ${pkg.package?.name} to a patched version.`
          });
        }
      }
    }

    return {
      name: 'OSV-Scanner (SCA / Dependency Audit)',
      status: 'completed',
      findings
    };
  } catch (error) {
    return {
      name: 'OSV-Scanner (SCA / Dependency Audit)',
      status: 'failed',
      reason: error.message,
      findings: []
    };
  }
};

module.exports = { runOsvScanner };

