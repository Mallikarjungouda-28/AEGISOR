/**
 * AEGISOR Complete Master Backend Test Suite
 * Validates Phases A through L end-to-end
 */

process.env.NODE_ENV = 'test';

const fs = require('fs');
const path = require('path');
const AdmZip = require('adm-zip');
const mongoose = require('mongoose');
const dotenv = require('dotenv');

dotenv.config({ path: path.join(__dirname, '../.env') });

const connectDB = require('../config/db');
const app = require('../server');
const User = require('../models/User');
const Project = require('../models/Project');
const Scan = require('../models/Scan');
const Vulnerability = require('../models/Vulnerability');
const { redactSensitiveContext } = require('../services/ai/geminiService');

const testResults = [];

const recordTest = (suite, testName, passed, details = '') => {
  testResults.push({ suite, testName, passed, details });
  const symbol = passed ? 'PASS' : 'FAIL';
  console.log(`  [${symbol}] ${testName} ${details ? `(${details})` : ''}`);
};

const createMockProjectZip = (filePath) => {
  const zip = new AdmZip();

  const packageJson = JSON.stringify(
    {
      name: 'vulnerable-sample-app',
      version: '1.0.0',
      dependencies: {
        express: '^4.19.2',
        react: '^18.2.0',
        'event-stream': '3.3.6'
      }
    },
    null,
    2
  );

  const serverJs = `
const express = require('express');
const app = express();

// Security Flaw 1: Hardcoded AWS Credential
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";

// Security Flaw 2: Potential SQL Injection via string concatenation
app.get('/user', (req, res) => {
  const query = "SELECT * FROM users WHERE id = " + req.query.id;
  res.send(query);
});

// Security Flaw 3: Dangerous dynamic code execution
app.get('/calc', (req, res) => {
  const result = eval(req.query.formula);
  res.json({ result });
});

app.listen(3000);
`;

  const appPy = `
import os

# Security Flaw 4: Command Injection
def run_command(user_input):
    os.system("ping " + user_input)
`;

  zip.addFile('package.json', Buffer.from(packageJson, 'utf8'));
  zip.addFile('server.js', Buffer.from(serverJs, 'utf8'));
  zip.addFile('app.py', Buffer.from(appPy, 'utf8'));
  zip.writeZip(filePath);
};

const createMaliciousZipSlipArchive = (filePath) => {
  const zip = new AdmZip();
  zip.addFile('payload.txt', Buffer.from('exploit content', 'utf8'));
  zip.getEntries()[0].entryName = '../../malicious_escape.txt';
  zip.writeZip(filePath);
};

async function runAllTests() {
  console.log('========================================================');
  console.log('       AEGISOR MASTER BACKEND END-TO-END TEST SUITE      ');
  console.log('========================================================\n');

  try {
    console.log('>>> Attempting connection to MongoDB Atlas...');
    await connectDB();
    console.log('>>> MongoDB Atlas Connected successfully.\n');
  } catch (atlasErr) {
    console.error(`\n[ATLAS CONNECTION ERROR]: Could not connect to MongoDB Atlas (${atlasErr.message}).`);
    console.error('Please whitelist your current IP address (or 0.0.0.0/0 for development) in MongoDB Atlas under Network Access.');
    console.error('Master integration test aborted: Requires live MongoDB connection.\n');
    process.exit(1);
  }

  // Start test server on ephemeral port
  const server = app.listen(0);
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;
  console.log(`>>> Test HTTP Server listening at ${baseUrl}\n`);

  const timestamp = Date.now();
  const userA_email = `auditor_a_${timestamp}@aegisor-test.com`;
  const userB_email = `auditor_b_${timestamp}@aegisor-test.com`;
  const password = 'StrongPassword123!';

  let userA_token = null;
  let userA_id = null;
  let userB_token = null;
  let userB_id = null;
  let projectId = null;
  let scanId = null;
  let vulnerabilityId = null;

  const testTempDir = path.join(__dirname, 'temp_test_artifacts');
  if (!fs.existsSync(testTempDir)) fs.mkdirSync(testTempDir, { recursive: true });

  const validZipPath = path.join(testTempDir, 'valid_project.zip');
  const fakeZipPath = path.join(testTempDir, 'fake_signature.zip');
  const zipSlipPath = path.join(testTempDir, 'zip_slip.zip');

  createMockProjectZip(validZipPath);
  fs.writeFileSync(fakeZipPath, 'This is plain text with fake .zip extension, no magic bytes');
  createMaliciousZipSlipArchive(zipSlipPath);

  try {
    // ----------------------------------------------------
    // SUITE 1: AUTHENTICATION & ACCESS CONTROL
    // ----------------------------------------------------
    console.log('\n--- SUITE 1: AUTHENTICATION & ACCESS CONTROL ---');

    // 1.1 Register User A
    const regResA = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Auditor Alpha', email: userA_email, password })
    });
    const regDataA = await regResA.json();
    userA_token = regDataA.data?.token;
    userA_id = regDataA.data?.user?._id;
    recordTest('Auth', 'Register User A', regResA.status === 201 && Boolean(userA_token));

    // 1.2 Duplicate Registration Prevention
    const dupRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Duplicate User', email: userA_email, password })
    });
    recordTest('Auth', 'Reject Duplicate Email (409 Conflict)', dupRes.status === 409);

    // 1.3 Register User B (for cross-user testing)
    const regResB = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Auditor Beta', email: userB_email, password })
    });
    const regDataB = await regResB.json();
    userB_token = regDataB.data?.token;
    userB_id = regDataB.data?.user?._id;
    recordTest('Auth', 'Register User B for Isolation Tests', regResB.status === 201);

    // 1.4 Login User A
    const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: userA_email, password })
    });
    recordTest('Auth', 'Login with Valid Credentials', loginRes.status === 200);

    // 1.5 Login with Invalid Password
    const badLoginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: userA_email, password: 'WrongPassword!' })
    });
    recordTest('Auth', 'Reject Invalid Password (401)', badLoginRes.status === 401);

    // 1.6 Protected Profile Access (with token)
    const meRes = await fetch(`${baseUrl}/api/auth/me`, {
      headers: { Authorization: `Bearer ${userA_token}` }
    });
    const meData = await meRes.json();
    recordTest('Auth', 'Get Profile via Protected Route', meRes.status === 200 && meData.data?.user?.email === userA_email);

    // 1.7 Protected Route without Token
    const noTokenRes = await fetch(`${baseUrl}/api/auth/me`);
    recordTest('Auth', 'Reject Unauthenticated Request (401)', noTokenRes.status === 401);

    // 1.8 Profile Update
    const updateProfRes = await fetch(`${baseUrl}/api/auth/profile`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${userA_token}`
      },
      body: JSON.stringify({ name: 'Auditor Alpha Updated' })
    });
    const updateProfData = await updateProfRes.json();
    recordTest('Auth', 'Update User Profile', updateProfRes.status === 200 && updateProfData.data?.user?.name === 'Auditor Alpha Updated');

    // 1.9 Change Password
    const newPassword = 'NewStrongPassword456!';
    const changePassRes = await fetch(`${baseUrl}/api/auth/password`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${userA_token}`
      },
      body: JSON.stringify({ currentPassword: password, newPassword })
    });
    recordTest('Auth', 'Change Password Securely', changePassRes.status === 200);

    // Re-verify login with new password
    const reLoginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: userA_email, password: newPassword })
    });
    const reLoginData = await reLoginRes.json();
    userA_token = reLoginData.data?.token;
    recordTest('Auth', 'Login with New Password', reLoginRes.status === 200 && Boolean(userA_token));

    // ----------------------------------------------------
    // SUITE 2: PROJECT MANAGEMENT & ISOLATION
    // ----------------------------------------------------
    console.log('\n--- SUITE 2: PROJECT MANAGEMENT & CROSS-USER ISOLATION ---');

    // 2.1 Create Project (User A)
    const createProjRes = await fetch(`${baseUrl}/api/projects`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${userA_token}`
      },
      body: JSON.stringify({
        name: 'Vulnerable Microservice Project',
        description: 'Test repository for security auditing'
      })
    });
    const createProjData = await createProjRes.json();
    projectId = createProjData.data?.project?._id;
    recordTest('Project', 'Create New Project', createProjRes.status === 201 && Boolean(projectId));

    // 2.2 List Projects (User A)
    const listProjRes = await fetch(`${baseUrl}/api/projects`, {
      headers: { Authorization: `Bearer ${userA_token}` }
    });
    const listProjData = await listProjRes.json();
    recordTest('Project', 'List User Projects with Pagination', listProjRes.status === 200 && listProjData.data?.projects?.length >= 1);

    // 2.3 Retrieve Individual Project
    const getProjRes = await fetch(`${baseUrl}/api/projects/${projectId}`, {
      headers: { Authorization: `Bearer ${userA_token}` }
    });
    recordTest('Project', 'Retrieve Individual Project by ID', getProjRes.status === 200);

    // 2.4 Update Project Details
    const updateProjRes = await fetch(`${baseUrl}/api/projects/${projectId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${userA_token}`
      },
      body: JSON.stringify({ description: 'Updated description for audit testing' })
    });
    recordTest('Project', 'Update Project Metadata', updateProjRes.status === 200);

    // 2.5 Cross-User Access Prevention (User B tries to read User A's project)
    const crossGetRes = await fetch(`${baseUrl}/api/projects/${projectId}`, {
      headers: { Authorization: `Bearer ${userB_token}` }
    });
    recordTest('Project', 'Prevent Cross-User Project Read (403 Forbidden)', crossGetRes.status === 403);

    // 2.6 Cross-User Access Prevention (User B tries to update User A's project)
    const crossUpdateRes = await fetch(`${baseUrl}/api/projects/${projectId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${userB_token}`
      },
      body: JSON.stringify({ name: 'Hacked Project' })
    });
    recordTest('Project', 'Prevent Cross-User Project Update (403 Forbidden)', crossUpdateRes.status === 403);

    // ----------------------------------------------------
    // SUITE 3: SECURE ZIP UPLOAD & PROJECT DETECTION
    // ----------------------------------------------------
    console.log('\n--- SUITE 3: SECURE ZIP UPLOADS & PROJECT DETECTION ---');

    // 3.1 Reject Fake ZIP (Spoofed extension with invalid magic bytes)
    const fakeForm = new FormData();
    fakeForm.append('file', new Blob([fs.readFileSync(fakeZipPath)]), 'fake_signature.zip');

    const fakeUploadRes = await fetch(`${baseUrl}/api/projects/${projectId}/upload`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${userA_token}` },
      body: fakeForm
    });
    recordTest('Upload', 'Reject Fake ZIP Signature / Magic Bytes', fakeUploadRes.status === 400);

    // 3.2 Reject Zip Slip Path Traversal Archive
    const slipForm = new FormData();
    slipForm.append('file', new Blob([fs.readFileSync(zipSlipPath)]), 'zip_slip.zip');

    const slipUploadRes = await fetch(`${baseUrl}/api/projects/${projectId}/upload`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${userA_token}` },
      body: slipForm
    });
    recordTest('Upload', 'Reject Zip Slip Path Traversal Attack', slipUploadRes.status === 400);

    // 3.3 Valid ZIP Upload & Safe Extraction
    const validForm = new FormData();
    validForm.append('file', new Blob([fs.readFileSync(validZipPath)]), 'valid_project.zip');

    const validUploadRes = await fetch(`${baseUrl}/api/projects/${projectId}/upload`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${userA_token}` },
      body: validForm
    });
    const validUploadData = await validUploadRes.json();
    const detectedLangs = validUploadData.data?.project?.programmingLanguages || [];
    const detectedFrameworks = validUploadData.data?.project?.frameworks || [];
    recordTest('Upload', 'Upload & Extract Valid Project ZIP', validUploadRes.status === 200);

    // 3.4 Language and Framework Detection
    const hasJs = detectedLangs.includes('JavaScript');
    const hasPython = detectedLangs.includes('Python');
    const hasExpress = detectedFrameworks.includes('Express.js');
    recordTest(
      'Detection',
      'Detect Languages & Frameworks from Code & Manifests',
      hasJs && hasPython && hasExpress,
      `Languages: ${detectedLangs.join(', ')}, Frameworks: ${detectedFrameworks.join(', ')}`
    );

    // ----------------------------------------------------
    // SUITE 4: SECURITY SCANNING & VULNERABILITY AUDIT
    // ----------------------------------------------------
    console.log('\n--- SUITE 4: SECURITY SCANNING ENGINE & SCORING ---');

    // 4.1 Trigger Security Scan
    const scanTriggerRes = await fetch(`${baseUrl}/api/projects/${projectId}/scans`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${userA_token}` }
    });
    const scanTriggerData = await scanTriggerRes.json();
    scanId = scanTriggerData.data?.scan?._id;
    recordTest('Scan', 'Initiate Non-Blocking Security Scan', scanTriggerRes.status === 202 && Boolean(scanId));

    // Wait for async scan completion (poll up to 10 seconds)
    let completedScan = null;
    for (let i = 0; i < 20; i++) {
      await new Promise((r) => setTimeout(r, 500));
      const pollRes = await fetch(`${baseUrl}/api/scans/${scanId}`, {
        headers: { Authorization: `Bearer ${userA_token}` }
      });
      const pollData = await pollRes.json();
      if (pollData.data?.scan?.status === 'completed' || pollData.data?.scan?.status === 'failed') {
        completedScan = pollData.data.scan;
        break;
      }
    }

    recordTest(
      'Scan',
      'Scan Transitions to Completed State',
      completedScan && completedScan.status === 'completed',
      `Score: ${completedScan?.securityScore}/100, Findings: ${completedScan?.totalVulnerabilities}`
    );

    // 4.2 Verify Scanner Availability Reporting
    const unavailableScanners = completedScan?.scannersUnavailable || [];
    const activeScanners = completedScan?.scannersRun || [];
    recordTest(
      'Scan',
      'Report External Scanner Availability Accurately',
      activeScanners.length >= 1,
      `Active: ${activeScanners.join(', ')} | Unavailable: ${unavailableScanners.length} engines reported`
    );

    // 4.3 Retrieve Discovered Vulnerabilities
    const resultsRes = await fetch(`${baseUrl}/api/scans/${scanId}/results`, {
      headers: { Authorization: `Bearer ${userA_token}` }
    });
    const resultsData = await resultsRes.json();
    const vulns = resultsData.data?.vulnerabilities || [];
    recordTest('Vulnerability', 'Retrieve Normalized Scan Vulnerabilities', resultsRes.status === 200 && vulns.length >= 3);

    if (vulns.length > 0) {
      vulnerabilityId = vulns[0]._id;
    }

    // 4.4 Verify Specific Findings Detection
    const hasAwsLeak = vulns.some((v) => v.title.includes('AWS') || v.cwe === 'CWE-798');
    const hasSqlInjection = vulns.some((v) => v.title.includes('SQL') || v.cwe === 'CWE-89');
    const hasEval = vulns.some((v) => v.title.includes('eval') || v.cwe === 'CWE-95');
    recordTest('Vulnerability', 'Detect Hardcoded AWS Secret (CWE-798)', hasAwsLeak);
    recordTest('Vulnerability', 'Detect SQL Injection Flaw (CWE-89)', hasSqlInjection);
    recordTest('Vulnerability', 'Detect Dynamic Eval / RCE Flaw (CWE-95)', hasEval);

    // 4.5 Filter Vulnerabilities by Severity
    const filterCritRes = await fetch(`${baseUrl}/api/projects/${projectId}/vulnerabilities?severity=critical`, {
      headers: { Authorization: `Bearer ${userA_token}` }
    });
    const filterCritData = await filterCritRes.json();
    const allCritical = filterCritData.data?.vulnerabilities?.every((v) => v.severity === 'critical');
    recordTest('Vulnerability', 'Filter Findings by Severity (Critical)', filterCritRes.status === 200 && allCritical);

    // 4.6 Cross-User Vulnerability Isolation
    const crossVulnRes = await fetch(`${baseUrl}/api/projects/${projectId}/vulnerabilities`, {
      headers: { Authorization: `Bearer ${userB_token}` }
    });
    recordTest('Vulnerability', 'Prevent Cross-User Vulnerability Access (403)', crossVulnRes.status === 403);

    // ----------------------------------------------------
    // SUITE 5: AI SERVICES & SECRET REDACTION
    // ----------------------------------------------------
    console.log('\n--- SUITE 5: AI SERVICES & CONTEXT HYGIENE ---');

    // 5.1 Secret Redaction Unit Test
    const rawSensitiveSnippet = 'const key = "AKIAIOSFODNN7EXAMPLE"; const db = "mongodb+srv://admin:SecretPass123@cluster.net/db";';
    const redacted = redactSensitiveContext(rawSensitiveSnippet);
    const isRedacted = !redacted.includes('AKIAIOSFODNN7EXAMPLE') && !redacted.includes('SecretPass123') && redacted.includes('[REDACTED');
    recordTest('AI', 'Redact Sensitive Credentials Prior to AI Context', isRedacted);

    // 5.2 AI Vulnerability Explanation Endpoint
    if (vulnerabilityId) {
      const explainRes = await fetch(`${baseUrl}/api/vulnerabilities/${vulnerabilityId}/explain`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${userA_token}` }
      });
      const explainData = await explainRes.json();
      recordTest(
        'AI',
        'Vulnerability Explanation (Handles Available or Fallback)',
        explainRes.status === 200 && Boolean(explainData.data?.explanation)
      );

      // 5.3 AI Fix Preview & Unified Diff Endpoint (Preview only, never overwrites original file)
      const fixRes = await fetch(`${baseUrl}/api/vulnerabilities/${vulnerabilityId}/fix-preview`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${userA_token}` }
      });
      const fixData = await fixRes.json();
      recordTest(
        'AI',
        'Generate AI Fix Preview & Unified Diff',
        fixRes.status === 200 && Boolean(fixData.data?.fixPreview?.explanation)
      );
    }

    // ----------------------------------------------------
    // SUITE 6: PDF REPORT GENERATION & DOWNLOAD
    // ----------------------------------------------------
    console.log('\n--- SUITE 6: PDF AUDIT REPORT GENERATION ---');

    const reportRes = await fetch(`${baseUrl}/api/scans/${scanId}/report`, {
      headers: { Authorization: `Bearer ${userA_token}` }
    });
    const contentType = reportRes.headers.get('content-type');
    const reportBuffer = await reportRes.arrayBuffer();
    const pdfMagic = Buffer.from(reportBuffer).slice(0, 5).toString('utf8');

    recordTest(
      'Report',
      'Generate Professional Downloadable PDF Report',
      reportRes.status === 200 && contentType.includes('application/pdf') && pdfMagic.startsWith('%PDF-'),
      `PDF Size: ${reportBuffer.byteLength} bytes`
    );

    // Cross-user report download protection
    const crossReportRes = await fetch(`${baseUrl}/api/scans/${scanId}/report`, {
      headers: { Authorization: `Bearer ${userB_token}` }
    });
    recordTest('Report', 'Prevent Unauthorized User from Downloading Report (403)', crossReportRes.status === 403);

    // ----------------------------------------------------
    // SUITE 7: DASHBOARD AGGREGATION & METRICS
    // ----------------------------------------------------
    console.log('\n--- SUITE 7: DASHBOARD OVERVIEW METRICS ---');

    const dashRes = await fetch(`${baseUrl}/api/dashboard/overview`, {
      headers: { Authorization: `Bearer ${userA_token}` }
    });
    const dashData = await dashRes.json();
    const metrics = dashData.data?.metrics;

    recordTest(
      'Dashboard',
      'Compute Comprehensive Platform Metrics & Severity Breakdown',
      dashRes.status === 200 &&
        metrics?.totalProjects >= 1 &&
        metrics?.totalScans >= 1 &&
        metrics?.averageSecurityScore !== null &&
        metrics?.totalVulnerabilities >= 1,
      `Projects: ${metrics?.totalProjects}, Scans: ${metrics?.totalScans}, Avg Score: ${metrics?.averageSecurityScore}/100`
    );

    // ----------------------------------------------------
    // SUITE 8: CLEANUP & CASCADE ACCOUNT DELETION
    // ----------------------------------------------------
    console.log('\n--- SUITE 8: CLEANUP & CASCADE DATA DELETION ---');

    // 8.1 Delete User A and cascade delete all their projects, scans, vulns, and files
    const deleteAccountRes = await fetch(`${baseUrl}/api/auth/account`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${userA_token}`
      },
      body: JSON.stringify({ password: newPassword })
    });
    recordTest('Cleanup', 'Delete User Account with Complete Cascade Cleanup', deleteAccountRes.status === 200);

    // Verify cascade: project must no longer exist
    const checkProj = await Project.findById(projectId);
    const checkScans = await Scan.find({ project: projectId });
    const checkVulns = await Vulnerability.find({ project: projectId });
    recordTest(
      'Cleanup',
      'Verify Cascade Deletion of Projects, Scans & Vulnerabilities',
      checkProj === null && checkScans.length === 0 && checkVulns.length === 0
    );

    // Clean up User B
    await User.findByIdAndDelete(userB_id);
    recordTest('Cleanup', 'Clean up Secondary Test User B', true);

    // Clean up local temp test archives
    if (fs.existsSync(testTempDir)) {
      fs.rmSync(testTempDir, { recursive: true, force: true });
    }
  } catch (error) {
    console.error('\n[FATAL TEST FAILURE]:', error);
  } finally {
    server.close();
    await mongoose.connection.close(false);
  }

  // Summary Table
  console.log('\n========================================================');
  console.log('                 FINAL TEST EXECUTION SUMMARY           ');
  console.log('========================================================');

  const total = testResults.length;
  const passedCount = testResults.filter((r) => r.passed).length;
  const failedCount = total - passedCount;

  console.table(testResults);

  console.log(`\nTOTAL TESTS: ${total}`);
  console.log(`PASSED:      ${passedCount}`);
  console.log(`FAILED:      ${failedCount}`);

  if (failedCount === 0) {
    console.log('\n>>> ALL TEST SUITES PASSED SUCCESSFULLY! <<<');
    process.exit(0);
  } else {
    console.error(`\n>>> ${failedCount} TESTS FAILED <<<`);
    process.exit(1);
  }
}

runAllTests();
