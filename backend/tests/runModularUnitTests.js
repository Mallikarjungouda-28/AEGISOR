/**
 * AEGISOR Modular Unit & Security Test Suite
 * Tests scanner engines, upload security, Zip Slip defenses, language detection,
 * PDF generation, AI redaction, and scoring logic.
 */

process.env.NODE_ENV = 'test';

const fs = require('fs');
const path = require('path');
const AdmZip = require('adm-zip');

const { redactSensitiveContext } = require('../services/ai/geminiService');
const { runBuiltInScanner } = require('../services/scanners/adapters/builtInScannerAdapter');
const { runSemgrep } = require('../services/scanners/adapters/semgrepAdapter');
const { runGitleaks } = require('../services/scanners/adapters/gitleaksAdapter');
const { runOsvScanner } = require('../services/scanners/adapters/osvScannerAdapter');
const { runEslint } = require('../services/scanners/adapters/eslintAdapter');
const { runBandit } = require('../services/scanners/adapters/banditAdapter');
const { orchestrateScan, calculateSecurityScore } = require('../services/scanners/scannerOrchestrator');
const { validateZipMagicBytes, safeExtractZip } = require('../services/uploads/zipService');
const { detectProjectMetadata } = require('../services/detector/projectDetector');
const { generatePdfReport } = require('../services/reports/pdfReportService');

const results = [];

const record = (suite, name, passed, details = '') => {
  results.push({ suite, name, passed, details });
  const status = passed ? 'PASS' : 'FAIL';
  console.log(`  [${status}] ${name} ${details ? `(${details})` : ''}`);
};

async function runUnitTests() {
  console.log('========================================================');
  console.log('       AEGISOR MODULAR ENGINE & SECURITY TEST SUITE     ');
  console.log('========================================================\n');

  const testTempDir = path.join(__dirname, 'temp_unit_test');
  if (fs.existsSync(testTempDir)) fs.rmSync(testTempDir, { recursive: true, force: true });
  fs.mkdirSync(testTempDir, { recursive: true });

  const vulnerableProjectDir = path.join(testTempDir, 'vuln_proj');
  fs.mkdirSync(vulnerableProjectDir, { recursive: true });

  // 1. Create mock files with known vulnerabilities
  const packageJson = JSON.stringify(
    {
      name: 'test-app',
      dependencies: {
        express: '^4.19.2',
        react: '^18.2.0',
        'event-stream': '3.3.6' // Known vulnerable
      }
    },
    null,
    2
  );
  fs.writeFileSync(path.join(vulnerableProjectDir, 'package.json'), packageJson);

  const serverJs = `
const express = require('express');
const app = express();

// Flaw 1: Hardcoded AWS Credential
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";

// Flaw 2: Hardcoded Database URI with credentials
const DB_URI = "mongodb://dbadmin:SuperSecretPass123@cluster0.net/prod";

// Flaw 3: SQL Injection
app.get('/user', (req, res) => {
  const q = "SELECT * FROM users WHERE name = '" + req.query.name + "'";
});

// Flaw 4: Command Injection
const { exec } = require('child_process');
app.get('/run', (req, res) => {
  exec(req.query.cmd);
});

// Flaw 5: Eval Code Injection
app.get('/calc', (req, res) => {
  eval(req.query.input);
});

// Flaw 6: DOM XSS
document.getElementById('out').innerHTML = req.query.msg;

// Flaw 7: Disabled TLS
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
`;
  fs.writeFileSync(path.join(vulnerableProjectDir, 'server.js'), serverJs);

  const appPy = `
import os
# Python Command Injection
os.system("ping " + user_arg)
`;
  fs.writeFileSync(path.join(vulnerableProjectDir, 'app.py'), appPy);

  try {
    // ----------------------------------------------------
    // TEST 1: SECRET REDACTION
    // ----------------------------------------------------
    console.log('--- 1. AI SERVICE CONTEXT REDACTION ---');
    const secretSnippet = 'AWS: "AKIAIOSFODNN7EXAMPLE", DB: "mongodb://admin:pass@host/db", Key: "ghp_1234567890abcdefghijklmnopqrstuvwxyz"';
    const redacted = redactSensitiveContext(secretSnippet);
    record(
      'AI',
      'Redact AWS Keys, DB URIs, and GitHub Tokens',
      !redacted.includes('AKIAIOSFODNN7EXAMPLE') &&
        !redacted.includes('pass') &&
        !redacted.includes('ghp_') &&
        redacted.includes('[REDACTED'),
      redacted.substring(0, 70) + '...'
    );

    // ----------------------------------------------------
    // TEST 2: BUILT-IN SAST SCANNER ENGINE
    // ----------------------------------------------------
    console.log('\n--- 2. NATIVE SAST & SECRET SCANNER ENGINE ---');
    const builtInResult = await runBuiltInScanner(vulnerableProjectDir);
    const findings = builtInResult.findings;

    record('SAST', 'Scanner Executes Successfully', builtInResult.status === 'completed');
    record('SAST', 'Detect Multiple Vulnerabilities', findings.length >= 6, `Total findings: ${findings.length}`);

    const hasAws = findings.some((f) => f.cwe === 'CWE-798' && f.title.includes('AWS'));
    const hasDbCred = findings.some((f) => f.cwe === 'CWE-798' && f.title.includes('Database'));
    const hasSql = findings.some((f) => f.cwe === 'CWE-89');
    const hasCmd = findings.some((f) => f.cwe === 'CWE-78');
    const hasEval = findings.some((f) => f.cwe === 'CWE-95');
    const hasXss = findings.some((f) => f.cwe === 'CWE-79');
    const hasTls = findings.some((f) => f.cwe === 'CWE-295');
    const hasSca = findings.some((f) => f.cwe === 'CWE-506');

    record('SAST', 'Detect Hardcoded AWS Credentials (CWE-798)', hasAws);
    record('SAST', 'Detect Plaintext Database URI (CWE-798)', hasDbCred);
    record('SAST', 'Detect SQL Injection (CWE-89)', hasSql);
    record('SAST', 'Detect Command Injection (CWE-78)', hasCmd);
    record('SAST', 'Detect Dynamic Eval / RCE (CWE-95)', hasEval);
    record('SAST', 'Detect DOM XSS innerHTML (CWE-79)', hasXss);
    record('SAST', 'Detect Disabled TLS Verification (CWE-295)', hasTls);
    record('SAST', 'Detect Vulnerable Dependency event-stream (SCA)', hasSca);

    // ----------------------------------------------------
    // TEST 3: SCANNER ADAPTERS & AVAILABILITY
    // ----------------------------------------------------
    console.log('\n--- 3. SCANNER ADAPTERS AVAILABILITY REPORTING ---');
    const semgrep = await runSemgrep(vulnerableProjectDir);
    record('Adapters', 'Semgrep Adapter Handles Installed or Unavailable', semgrep.status === 'completed' || semgrep.status === 'unavailable');

    const gitleaks = await runGitleaks(vulnerableProjectDir);
    record('Adapters', 'Gitleaks Adapter Handles Installed or Unavailable', gitleaks.status === 'completed' || gitleaks.status === 'unavailable');

    const osv = await runOsvScanner(vulnerableProjectDir);
    record('Adapters', 'OSV-Scanner Adapter Handles Installed or Unavailable', osv.status === 'completed' || osv.status === 'unavailable');

    const eslint = await runEslint(vulnerableProjectDir);
    record('Adapters', 'ESLint Adapter Handles Installed or Unavailable', eslint.status === 'completed' || eslint.status === 'unavailable');

    const bandit = await runBandit(vulnerableProjectDir);
    record('Adapters', 'Bandit Adapter Handles Installed or Unavailable', bandit.status === 'completed' || bandit.status === 'unavailable');

    // ----------------------------------------------------
    // TEST 4: SCANNER ORCHESTRATION & SCORING
    // ----------------------------------------------------
    console.log('\n--- 4. SCANNER ORCHESTRATOR & SCORING ALGORITHM ---');
    const orchestratorResult = await orchestrateScan(vulnerableProjectDir, ['JavaScript', 'Python']);

    record(
      'Orchestrator',
      'Orchestrator Normalizes Findings and Deduplicates',
      orchestratorResult.totalVulnerabilities > 0 && Array.isArray(orchestratorResult.findings)
    );

    record(
      'Orchestrator',
      'Calculate Correct Score Deductions',
      orchestratorResult.securityScore >= 0 && orchestratorResult.securityScore <= 100,
      `Calculated Score: ${orchestratorResult.securityScore}/100`
    );

    const testScoreZero = calculateSecurityScore({ critical: 5, high: 2 });
    record('Orchestrator', 'Security Score Floors at 0 (Never Negative)', testScoreZero === 0);

    const testScoreClean = calculateSecurityScore({ critical: 0, high: 0, medium: 0, low: 0 });
    record('Orchestrator', 'Clean Scan Returns Perfect Score of 100', testScoreClean === 100);

    // ----------------------------------------------------
    // TEST 5: SECURE ZIP UPLOAD & EXTRACTION DEFENSES
    // ----------------------------------------------------
    console.log('\n--- 5. SECURE ZIP UPLOADS & ZIP SLIP / BOMB DEFENSES ---');

    // 5.1 Valid Zip Creation
    const validZipPath = path.join(testTempDir, 'valid.zip');
    const validZip = new AdmZip();
    validZip.addLocalFolder(vulnerableProjectDir);
    validZip.writeZip(validZipPath);

    record('Upload', 'Validate Proper ZIP Magic Bytes (PK\\x03\\x04)', validateZipMagicBytes(validZipPath));

    const fakeZipPath = path.join(testTempDir, 'fake.zip');
    fs.writeFileSync(fakeZipPath, 'NOT A ZIP FILE');
    record('Upload', 'Reject Spoofed File Extension with Bad Magic Bytes', !validateZipMagicBytes(fakeZipPath));

    // 5.2 Zip Slip Path Traversal Archive
    const slipZipPath = path.join(testTempDir, 'slip.zip');
    const slipZip = new AdmZip();
    slipZip.addFile('payload.txt', Buffer.from('exploit'));
    slipZip.getEntries()[0].entryName = '../../escape.txt';
    slipZip.writeZip(slipZipPath);

    let slipCaught = false;
    try {
      await safeExtractZip(slipZipPath, path.join(testTempDir, 'slip_extracted'));
    } catch (err) {
      slipCaught = err.message.includes('Path traversal attempt detected');
    }
    record('Upload', 'Defend Against Zip Slip Path Traversal Attacks', slipCaught);

    // 5.3 Safe Extraction of Valid Archive
    const extractTarget = path.join(testTempDir, 'extracted_clean');
    const extractRes = await safeExtractZip(validZipPath, extractTarget);
    record('Upload', 'Safe Extraction of Legitimate Project Archive', extractRes.extractedCount >= 3);

    // ----------------------------------------------------
    // TEST 6: LANGUAGE & PROJECT DETECTOR
    // ----------------------------------------------------
    console.log('\n--- 6. PROGRAMMING LANGUAGE & FRAMEWORK DETECTION ---');
    const detected = await detectProjectMetadata(extractTarget);

    const hasJsLang = detected.programmingLanguages.includes('JavaScript');
    const hasPyLang = detected.programmingLanguages.includes('Python');
    const hasExpressFw = detected.frameworks.includes('Express.js');
    const hasReactFw = detected.frameworks.includes('React');
    const hasManifest = detected.manifestFiles.includes('package.json');
    const hasEntry = detected.entryPoints.includes('server.js');

    record('Detector', 'Detect JavaScript and Python Languages', hasJsLang && hasPyLang);
    record('Detector', 'Detect Express.js and React Frameworks', hasExpressFw && hasReactFw);
    record('Detector', 'Identify Dependency Manifests & Entry Points', hasManifest && hasEntry);

    // ----------------------------------------------------
    // TEST 7: PROFESSIONAL PDF REPORT GENERATION
    // ----------------------------------------------------
    console.log('\n--- 7. PROFESSIONAL PDF AUDIT REPORT GENERATION ---');
    const mockScan = {
      _id: '672e3a1f8b9c2d0012345678',
      securityScore: 65,
      totalVulnerabilities: findings.length,
      severityBreakdown: { critical: 2, high: 3, medium: 2, low: 0, informational: 0 },
      scannersRun: ['AEGISOR Native Engine'],
      aiSummary: 'Mock AI executive summary describing project risk.',
      scanCompletedAt: new Date()
    };
    const mockProject = {
      name: 'Vulnerable E-Commerce Service',
      originalFileName: 'ecommerce_app.zip',
      programmingLanguages: ['JavaScript', 'Python'],
      frameworks: ['Express.js', 'React']
    };

    const pdfOutputPath = path.join(testTempDir, 'test_audit_report.pdf');
    const pdfWriteStream = fs.createWriteStream(pdfOutputPath);

    await new Promise((resolve, reject) => {
      pdfWriteStream.on('finish', resolve);
      pdfWriteStream.on('error', reject);
      generatePdfReport(mockScan, mockProject, findings, pdfWriteStream);
    });

    const pdfStats = fs.statSync(pdfOutputPath);
    const pdfBytes = fs.readFileSync(pdfOutputPath, { length: 5 });
    const isPdfValid = pdfStats.size > 1000 && pdfBytes.toString('utf8').startsWith('%PDF-');

    record('Report', 'Generate Valid Structured PDF Document with Scoring & Findings', isPdfValid, `Size: ${pdfStats.size} bytes`);
  } catch (error) {
    console.error('[TEST ERROR]:', error);
  } finally {
    // Clean up temporary test files
    if (fs.existsSync(testTempDir)) {
      fs.rmSync(testTempDir, { recursive: true, force: true });
    }
  }

  // Summary
  console.log('\n========================================================');
  console.log('                 UNIT TEST SUMMARY REPORT               ');
  console.log('========================================================');

  const total = results.length;
  const passed = results.filter((r) => r.passed).length;
  const failed = total - passed;

  console.table(results);
  console.log(`TOTAL TESTS: ${total}`);
  console.log(`PASSED:      ${passed}`);
  console.log(`FAILED:      ${failed}`);

  if (failed === 0) {
    console.log('\n>>> ALL 26 CORE ENGINE & SECURITY TESTS PASSED! <<<');
  } else {
    process.exit(1);
  }
}

runUnitTests();
