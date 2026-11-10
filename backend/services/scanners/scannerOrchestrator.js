const { runBuiltInScanner } = require('./adapters/builtInScannerAdapter');
const { runSemgrep } = require('./adapters/semgrepAdapter');
const { runGitleaks } = require('./adapters/gitleaksAdapter');
const { runOsvScanner } = require('./adapters/osvScannerAdapter');
const { runEslint } = require('./adapters/eslintAdapter');
const { runBandit } = require('./adapters/banditAdapter');

/**
 * Calculates a standardized security score from findings
 * Deductions: Critical -25, High -15, Medium -7, Low -2, Informational 0
 * @param {object} severityBreakdown
 * @returns {number} Score between 0 and 100
 */
const calculateSecurityScore = (severityBreakdown) => {
  let score = 100;
  score -= (severityBreakdown.critical || 0) * 25;
  score -= (severityBreakdown.high || 0) * 15;
  score -= (severityBreakdown.medium || 0) * 7;
  score -= (severityBreakdown.low || 0) * 2;
  return Math.max(0, Math.min(100, score));
};

/**
 * Orchestrates multi-engine security scanning for a project directory
 * @param {string} targetDir - Absolute path to extracted project
 * @param {Array<string>} languages - Detected project languages
 * @returns {Promise<object>}
 */
const orchestrateScan = async (targetDir, languages = []) => {
  const scannersRun = [];
  const scannersUnavailable = [];
  const scannersFailed = [];
  let rawFindings = [];

  // 1. Built-in SAST & Secret Scanner (always active)
  try {
    const builtInResult = await runBuiltInScanner(targetDir);
    scannersRun.push(builtInResult.name);
    rawFindings.push(...builtInResult.findings);
  } catch (err) {
    scannersFailed.push(`AEGISOR Native Engine (${err.message})`);
  }

  // 2. Semgrep (SAST)
  const semgrepResult = await runSemgrep(targetDir);
  if (semgrepResult.status === 'completed') {
    scannersRun.push(semgrepResult.name);
    rawFindings.push(...semgrepResult.findings);
  } else if (semgrepResult.status === 'unavailable') {
    scannersUnavailable.push(`${semgrepResult.name}: ${semgrepResult.reason}`);
  } else {
    scannersFailed.push(`${semgrepResult.name}: ${semgrepResult.reason}`);
  }

  // 3. Gitleaks (Secrets)
  const gitleaksResult = await runGitleaks(targetDir);
  if (gitleaksResult.status === 'completed') {
    scannersRun.push(gitleaksResult.name);
    rawFindings.push(...gitleaksResult.findings);
  } else if (gitleaksResult.status === 'unavailable') {
    scannersUnavailable.push(`${gitleaksResult.name}: ${gitleaksResult.reason}`);
  } else {
    scannersFailed.push(`${gitleaksResult.name}: ${gitleaksResult.reason}`);
  }

  // 4. OSV-Scanner (SCA)
  const osvResult = await runOsvScanner(targetDir);
  if (osvResult.status === 'completed') {
    scannersRun.push(osvResult.name);
    rawFindings.push(...osvResult.findings);
  } else if (osvResult.status === 'unavailable') {
    scannersUnavailable.push(`${osvResult.name}: ${osvResult.reason}`);
  } else {
    scannersFailed.push(`${osvResult.name}: ${osvResult.reason}`);
  }

  // 5. ESLint (JavaScript / TypeScript specific)
  const isJsOrTs = languages.some((l) => /javascript|typescript/i.test(l));
  if (isJsOrTs) {
    const eslintResult = await runEslint(targetDir);
    if (eslintResult.status === 'completed') {
      scannersRun.push(eslintResult.name);
      rawFindings.push(...eslintResult.findings);
    } else if (eslintResult.status === 'unavailable') {
      scannersUnavailable.push(`${eslintResult.name}: ${eslintResult.reason}`);
    } else {
      scannersFailed.push(`${eslintResult.name}: ${eslintResult.reason}`);
    }
  }

  // 6. Bandit (Python specific)
  const isPython = languages.some((l) => /python/i.test(l));
  if (isPython) {
    const banditResult = await runBandit(targetDir);
    if (banditResult.status === 'completed') {
      scannersRun.push(banditResult.name);
      rawFindings.push(...banditResult.findings);
    } else if (banditResult.status === 'unavailable') {
      scannersUnavailable.push(`${banditResult.name}: ${banditResult.reason}`);
    } else {
      scannersFailed.push(`${banditResult.name}: ${banditResult.reason}`);
    }
  }

  // Deduplicate findings by (file + line + title/cwe)
  const seen = new Set();
  const normalizedFindings = [];
  const severityBreakdown = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0
  };

  for (const finding of rawFindings) {
    const key = `${finding.affectedFile}:${finding.lineNumber}:${finding.cwe || finding.title}`;
    if (!seen.has(key)) {
      seen.add(key);
      const sev = (finding.severity || 'medium').toLowerCase();
      if (severityBreakdown[sev] !== undefined) {
        severityBreakdown[sev]++;
      } else {
        severityBreakdown.medium++;
      }
      normalizedFindings.push({
        ...finding,
        severity: sev
      });
    }
  }

  const securityScore = calculateSecurityScore(severityBreakdown);

  return {
    securityScore,
    totalVulnerabilities: normalizedFindings.length,
    severityBreakdown,
    scannersRun,
    scannersUnavailable,
    scannersFailed,
    findings: normalizedFindings
  };
};

module.exports = {
  orchestrateScan,
  calculateSecurityScore
};

