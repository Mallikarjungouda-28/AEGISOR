/**
 * AEGISOR Phase 2 Comprehensive Storage & Background Scanning Test Suite
 *
 * Explicitly separates:
 *   - Suite A: [MOCKED] Deterministic Supabase & Error Handling Unit Tests
 *   - Suite B: [LIVE SUPABASE + ATLAS] Real Cloud Storage, Private Bucket Access,
 *              Signed Worker Invocation, Idempotency & Temp Cleanup Integration Tests
 */

process.env.NODE_ENV = 'test';

const fs = require('fs');
const path = require('path');
const os = require('os');
const AdmZip = require('adm-zip');
const mongoose = require('mongoose');
const dotenv = require('dotenv');

dotenv.config({ path: path.join(__dirname, '../.env') });

const connectDB = require('../config/db');
const app = require('../app');
const User = require('../models/User');
const Project = require('../models/Project');
const Scan = require('../models/Scan');
const Vulnerability = require('../models/Vulnerability');
const {
  _setMockSupabaseClient,
  isSupabaseConfigured,
  getStorageBucket,
  uploadProjectArchive,
  getSignedDownloadUrl,
  downloadProjectArchive,
  deleteProjectArchive
} = require('../services/storage/supabaseStorageService');
const { runScanPipeline } = require('../services/scanners/scanExecutionService');
const { handler: backgroundHandler } = require('../functions/scan-background');
const { signWorkerPayload, sanitizeErrorMessage } = require('../utils/workerAuth');
const generateToken = require('../utils/generateToken');

const results = [];
const record = (mode, name, passed, details = '') => {
  results.push({ mode, name, passed, details });
  const sym = passed ? 'PASS' : 'FAIL';
  console.log(`  [${mode}] [${sym}] ${name} ${details ? `(${details})` : ''}`);
};

const createSampleZip = (destPath) => {
  const zip = new AdmZip();
  zip.addFile(
    'package.json',
    Buffer.from(JSON.stringify({ name: 'phase2-cloud-app', version: '1.0.0', dependencies: { express: '^4.19.2' } }))
  );
  zip.addFile(
    'server.js',
    Buffer.from(
      'const express = require("express");\nconst AWS_KEY = "AKIAIOSFODNN7EXAMPLE";\nconst q = "SELECT * FROM users WHERE id = " + req.query.id;\n'
    )
  );
  zip.writeZip(destPath);
};

async function runMockedStorageSuite(sampleZipPath) {
  console.log('--- SUITE A: [MOCKED] SUPABASE STORAGE UNIT TESTS ---');

  const storedObjects = new Map();

  const mockClient = {
    storage: {
      from: (bucketName) => ({
        upload: async (key, buffer) => {
          if (key.includes('fail_upload')) {
            return { data: null, error: { message: 'Simulated mock upload timeout' } };
          }
          storedObjects.set(`${bucketName}/${key}`, Buffer.from(buffer));
          return { data: { path: key }, error: null };
        },
        download: async (key) => {
          const item = storedObjects.get(`${bucketName}/${key}`);
          if (!item) return { data: null, error: { message: 'Object not found in mock bucket' } };
          return { data: item, error: null };
        },
        createSignedUrl: async (key, expiresIn) => {
          if (!storedObjects.has(`${bucketName}/${key}`)) {
            return { data: null, error: { message: 'Missing key for signed URL' } };
          }
          return {
            data: { signedUrl: `https://mock.supabase.local/sign/${bucketName}/${key}?exp=${expiresIn}` },
            error: null
          };
        },
        remove: async (keys) => {
          for (const k of keys) storedObjects.delete(`${bucketName}/${k}`);
          return { data: keys, error: null };
        },
        list: async (prefix) => {
          const files = [];
          for (const fullKey of storedObjects.keys()) {
            const rel = fullKey.replace(`${bucketName}/`, '');
            if (rel.startsWith(prefix + '/')) {
              files.push({ name: rel.slice(prefix.length + 1) });
            }
          }
          return { data: files, error: null };
        }
      })
    }
  };

  _setMockSupabaseClient(mockClient);

  try {
    // 1. Upload with unique path
    const up1 = await uploadProjectArchive('proj123', sampleZipPath, 'app.zip');
    const up2 = await uploadProjectArchive('proj123', sampleZipPath, 'app.zip');
    record(
      'MOCKED',
      'Upload generates unique storage keys & persists archive',
      Boolean(up1.storageKey) && up1.storageKey !== up2.storageKey && up1.bucket === getStorageBucket(),
      `Key1: ${path.basename(up1.storageKey)}`
    );

    // 2. Download
    const dlBuf = await downloadProjectArchive(up1.storageKey);
    const origBuf = fs.readFileSync(sampleZipPath);
    record(
      'MOCKED',
      'Download retrieves exact binary ZIP archive bytes',
      Buffer.isBuffer(dlBuf) && Buffer.compare(dlBuf, origBuf) === 0
    );

    // 3. Signed URL
    const sUrl = await getSignedDownloadUrl(up1.storageKey, 90);
    record('MOCKED', 'Generates time-limited signed URL for private archive', sUrl.includes('?exp=90'));

    // 4. Path traversal guard
    let traversalBlocked = false;
    try {
      await downloadProjectArchive('../../etc/passwd');
    } catch (e) {
      traversalBlocked = e.message.includes('Illegal path characters');
    }
    record('MOCKED', 'Blocks path traversal characters in storage keys', traversalBlocked);

    // 5. Delete
    const del1 = await deleteProjectArchive(up1.storageKey);
    const del2 = await deleteProjectArchive(up2.storageKey);
    record('MOCKED', 'Delete removes stored ZIP archives cleanly', del1 === true && del2 === true && storedObjects.size === 0);

    // 6. Error sanitization
    const scrubbed = sanitizeErrorMessage(
      `Failed connecting with Bearer eyJhbGciOiJIUzI1NiJ9.abcdefghijk.lmnopqrstuv and ${process.env.SUPABASE_SECRET_KEY || 'sb_secret_test123'}`
    );
    record(
      'MOCKED',
      'Error sanitizer strips JWTs and secrets from stored scan errors',
      !scrubbed.includes('eyJhbGci') && !scrubbed.includes(process.env.SUPABASE_SECRET_KEY || 'sb_secret_test123')
    );
  } finally {
    _setMockSupabaseClient(null);
  }
}

async function runPhase2Tests() {
  console.log('========================================================');
  console.log('  AEGISOR PHASE 2 STORAGE & BACKGROUND SCAN VERIFICATION');
  console.log('========================================================\n');

  const testTempDir = path.join(os.tmpdir(), 'aegisor-phase2-suite');
  if (!fs.existsSync(testTempDir)) fs.mkdirSync(testTempDir, { recursive: true });
  const sampleZipPath = path.join(testTempDir, 'sample_cloud_project.zip');
  createSampleZip(sampleZipPath);

  // Run mocked tests first
  await runMockedStorageSuite(sampleZipPath);

  console.log('\n>>> Connecting to MongoDB Atlas for live integration verification...');
  await connectDB();
  console.log('>>> MongoDB Atlas connected.\n');

  const server = app.listen(0);
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  let userA = null;
  let userB = null;
  let tokenA = null;
  let tokenB = null;
  let projectA = null;
  let localProject = null;
  let uploadedLiveKey = null;

  try {
    const ts = Date.now();
    userA = await User.create({
      name: 'Cloud Auditor Alpha',
      email: `phase2_a_${ts}@aegisor-test.com`,
      password: 'HashedPassword123!'
    });
    userB = await User.create({
      name: 'Unauthorized Beta',
      email: `phase2_b_${ts}@aegisor-test.com`,
      password: 'HashedPassword123!'
    });
    tokenA = generateToken(userA._id);
    tokenB = generateToken(userB._id);

    projectA = await Project.create({
      name: 'Phase 2 Cloud Repository',
      owner: userA._id,
      programmingLanguages: ['JavaScript'],
      frameworks: ['Express.js']
    });

    // ----------------------------------------------------
    // SUITE B: LIVE SUPABASE STORAGE + PRIVATE BUCKET ACCESS
    // ----------------------------------------------------
    const liveConfigured = isSupabaseConfigured();
    console.log('--- SUITE B: [LIVE SUPABASE] CLOUD STORAGE & PRIVATE ACCESS ---');

    if (!liveConfigured) {
      console.log('  [NOTICE] Live Supabase integration skipped (credentials missing).');
    } else {
      // B1. Upload to private bucket
      const uploadRes = await uploadProjectArchive(
        projectA._id.toString(),
        sampleZipPath,
        'sample_cloud_project.zip'
      );
      uploadedLiveKey = uploadRes.storageKey;
      projectA.storageKey = uploadedLiveKey;
      projectA.storageBucket = uploadRes.bucket;
      projectA.originalFileName = 'sample_cloud_project.zip';
      await projectA.save();

      record(
        'LIVE SUPABASE',
        'Upload ZIP archive to private project-archives bucket',
        Boolean(uploadedLiveKey) && uploadRes.bucket === 'project-archives',
        `Size: ${uploadRes.size} bytes`
      );

      // B2. Verify bucket is PRIVATE (public URL MUST be rejected!)
      const publicUrl = `${process.env.SUPABASE_URL.replace(/\/+$/, '')}/storage/v1/object/public/${uploadRes.bucket}/${uploadedLiveKey}`;
      const publicFetch = await fetch(publicUrl);
      record(
        'LIVE SUPABASE',
        'Verify private bucket blocks unauthenticated public URL access',
        !publicFetch.ok && [400, 403, 404].includes(publicFetch.status),
        `HTTP ${publicFetch.status}`
      );

      // B3. Secure Signed Download URL (authorized owner HTTP endpoint)
      const archiveApiRes = await fetch(`${baseUrl}/api/projects/${projectA._id}/archive`, {
        headers: { Authorization: `Bearer ${tokenA}` }
      });
      const archiveApiData = await archiveApiRes.json();
      const signedDownloadUrl = archiveApiData.data?.downloadUrl;

      let signedFetchOk = false;
      if (signedDownloadUrl) {
        const sFetch = await fetch(signedDownloadUrl);
        const sArr = await sFetch.arrayBuffer();
        signedFetchOk = sFetch.ok && Buffer.compare(Buffer.from(sArr), fs.readFileSync(sampleZipPath)) === 0;
      }
      record(
        'LIVE SUPABASE',
        'Owner generates signed URL and downloads exact ZIP over HTTPS',
        archiveApiRes.status === 200 && signedFetchOk
      );

      // B4. Cross-User Unauthorized Archive Download Blocked (403 Forbidden)
      const unauthArchiveRes = await fetch(`${baseUrl}/api/projects/${projectA._id}/archive`, {
        headers: { Authorization: `Bearer ${tokenB}` }
      });
      record(
        'LIVE SUPABASE',
        'Blocks unauthorized user from downloading private archive (403 Forbidden)',
        unauthArchiveRes.status === 403
      );

      // B5. Server-side stream download helper
      const directDownloadBuf = await downloadProjectArchive(uploadedLiveKey);
      record(
        'LIVE SUPABASE',
        'Backend helper downloads archive buffer from private bucket',
        Buffer.isBuffer(directDownloadBuf) && Buffer.compare(directDownloadBuf, fs.readFileSync(sampleZipPath)) === 0
      );
    }

    // ----------------------------------------------------
    // SUITE C: [LIVE] NETLIFY BACKGROUND FUNCTION & IDEMPOTENCY
    // ----------------------------------------------------
    console.log('\n--- SUITE C: [LIVE ATLAS + BACKGROUND WORKER] SCANNING ---');

    const bgScan = await Scan.create({
      project: projectA._id,
      initiatedBy: userA._id,
      status: 'pending'
    });

    // C1. Security check: Reject unauthenticated worker call
    const noAuthBgRes = await backgroundHandler(
      {
        headers: {},
        body: JSON.stringify({ scanId: bgScan._id.toString(), projectId: projectA._id.toString() })
      },
      {}
    );
    record(
      'BACKGROUND',
      'Rejects unauthenticated direct background worker invocation (401)',
      noAuthBgRes.statusCode === 401
    );

    // C2. Security check: Reject tampered HMAC signature
    const badSigRes = await backgroundHandler(
      {
        headers: {
          'x-aegisor-worker-timestamp': String(Date.now()),
          'x-aegisor-worker-signature': '00'.repeat(32)
        },
        body: JSON.stringify({ scanId: bgScan._id.toString(), projectId: projectA._id.toString() })
      },
      {}
    );
    record(
      'BACKGROUND',
      'Rejects tampered HMAC signature on background worker (401)',
      badSigRes.statusCode === 401
    );

    if (liveConfigured) {
      // C3. Execute authenticated background scan pulling directly from Supabase Storage (no local extractedPath)
      const signedHeaders = signWorkerPayload(bgScan._id.toString(), projectA._id.toString());
      const mockContext = { callbackWaitsForEmptyEventLoop: true };

      const bgSuccessRes = await backgroundHandler(
        {
          headers: signedHeaders,
          body: JSON.stringify({ scanId: bgScan._id.toString(), projectId: projectA._id.toString() })
        },
        mockContext
      );

      const completedScan = await Scan.findById(bgScan._id);
      const vulnCountFirstRun = await Vulnerability.countDocuments({ scan: bgScan._id });

      record(
        'LIVE BACKGROUND',
        'Background worker pulls ZIP from Supabase, scans in os.tmpdir, and updates Atlas',
        bgSuccessRes.statusCode === 200 &&
          completedScan.status === 'completed' &&
          vulnCountFirstRun >= 2 &&
          mockContext.callbackWaitsForEmptyEventLoop === false,
        `Vulns: ${vulnCountFirstRun}, Score: ${completedScan.securityScore}/100`
      );

      // C4. Verify temp file cleanup in os.tmpdir()
      const tmpScansDir = path.join(os.tmpdir(), 'aegisor-scans');
      const leftoverDirs = fs.existsSync(tmpScansDir)
        ? fs.readdirSync(tmpScansDir).filter((d) => d.startsWith(bgScan._id.toString()))
        : [];
      const leftoverZips = fs
        .readdirSync(os.tmpdir())
        .filter((f) => f.startsWith(`aegisor-scan-${bgScan._id.toString()}`));

      record(
        'LIVE BACKGROUND',
        'Temporary ZIP & extracted files in os.tmpdir() cleaned after completion',
        leftoverDirs.length === 0 && leftoverZips.length === 0
      );

      // C5. Duplicate invocation protection (idempotency)
      const dupRes = await backgroundHandler(
        {
          headers: signWorkerPayload(bgScan._id.toString(), projectA._id.toString()),
          body: JSON.stringify({ scanId: bgScan._id.toString(), projectId: projectA._id.toString() })
        },
        {}
      );
      const vulnCountAfterDup = await Vulnerability.countDocuments({ scan: bgScan._id });

      record(
        'LIVE BACKGROUND',
        'Duplicate invocation does not create duplicate vulnerabilities or corrupt scan',
        dupRes.statusCode === 200 && vulnCountAfterDup === vulnCountFirstRun,
        `Vulns remain: ${vulnCountAfterDup}`
      );
    }

    // C6. Scan status polling endpoint & authorization check
    const statusOkRes = await fetch(`${baseUrl}/api/scans/${bgScan._id}/status`, {
      headers: { Authorization: `Bearer ${tokenA}` }
    });
    const statusForbiddenRes = await fetch(`${baseUrl}/api/scans/${bgScan._id}/status`, {
      headers: { Authorization: `Bearer ${tokenB}` }
    });
    record(
      'LIVE ATLAS',
      'Scan status endpoint enforces owner-only access (200 owner / 403 unauthorized)',
      statusOkRes.status === 200 && statusForbiddenRes.status === 403
    );

    // C7. Background scan failure & temp cleanup when storageKey points to missing archive
    const failProject = await Project.create({
      name: 'Corrupt Missing Archive Project',
      owner: userA._id,
      storageKey: `projects/${userA._id}/does-not-exist-${ts}.zip`
    });
    const failScan = await Scan.create({
      project: failProject._id,
      initiatedBy: userA._id,
      status: 'pending'
    });

    const failBgRes = await backgroundHandler(
      {
        headers: signWorkerPayload(failScan._id.toString(), failProject._id.toString()),
        body: JSON.stringify({ scanId: failScan._id.toString(), projectId: failProject._id.toString() })
      },
      {}
    );
    const updatedFailScan = await Scan.findById(failScan._id);
    const secretLeaked =
      (updatedFailScan.errorMessage || '').includes(process.env.SUPABASE_SECRET_KEY || 'NEVER') ||
      (updatedFailScan.errorMessage || '').includes(process.env.SUPABASE_URL || 'NEVER');

    record(
      'LIVE BACKGROUND',
      'Failed background scan sets status=failed cleanly without leaking secrets',
      failBgRes.statusCode === 500 &&
        updatedFailScan.status === 'failed' &&
        Boolean(updatedFailScan.errorMessage) &&
        !secretLeaked,
      `Error saved: "${updatedFailScan.errorMessage.slice(0, 60)}..."`
    );

    // Clean up failProject
    await Scan.deleteMany({ project: failProject._id });
    await Project.findByIdAndDelete(failProject._id);

    // ----------------------------------------------------
    // SUITE D: LOCAL DEV COMPATIBILITY & CASCADE DELETION
    // ----------------------------------------------------
    console.log('\n--- SUITE D: LOCAL DEV COMPATIBILITY & CASCADE CLEANUP ---');

    // D1. Local folder scan without Supabase storageKey
    const localDir = path.join(testTempDir, 'local_dev_project');
    new AdmZip(sampleZipPath).extractAllTo(localDir, true);
    localProject = await Project.create({
      name: 'Local Dev Offline Project',
      owner: userA._id,
      extractedPath: localDir,
      programmingLanguages: ['JavaScript']
    });
    const localScan = await Scan.create({
      project: localProject._id,
      initiatedBy: userA._id,
      status: 'pending'
    });

    const completedLocal = await runScanPipeline({
      scanId: localScan._id,
      projectId: localProject._id,
      targetDir: localDir,
      languages: ['JavaScript']
    });
    record(
      'LOCAL DEV',
      'Local filesystem scan succeeds identically alongside cloud workflow',
      completedLocal.status === 'completed' && completedLocal.totalVulnerabilities >= 2
    );

    // D2. Project DELETE cascade deletes Supabase storage archive!
    if (liveConfigured && uploadedLiveKey) {
      const delProjectRes = await fetch(`${baseUrl}/api/projects/${projectA._id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${tokenA}` }
      });

      let deletedFromCloud = false;
      try {
        await downloadProjectArchive(uploadedLiveKey);
      } catch {
        deletedFromCloud = true;
      }
      uploadedLiveKey = null; // Already deleted via API cascade

      record(
        'LIVE SUPABASE',
        'DELETE /api/projects/:id deletes stored ZIP archive from Supabase bucket',
        delProjectRes.status === 200 && deletedFromCloud
      );
    }
  } catch (err) {
    console.error('[SUITE ERROR]:', err);
    record('ERROR', 'Unhandled test suite exception', false, err.message);
  } finally {
    console.log('\n>>> Cleaning up all test resources in MongoDB Atlas & Supabase...');
    if (uploadedLiveKey && isSupabaseConfigured()) {
      await deleteProjectArchive(uploadedLiveKey);
    }
    if (userA) {
      const projs = await Project.find({ owner: userA._id });
      const pids = projs.map((p) => p._id);
      if (pids.length > 0) {
        await Vulnerability.deleteMany({ project: { $in: pids } });
        await Scan.deleteMany({ project: { $in: pids } });
        await Project.deleteMany({ owner: userA._id });
      }
      await User.findByIdAndDelete(userA._id);
    }
    if (userB) {
      await User.findByIdAndDelete(userB._id);
    }
    if (fs.existsSync(testTempDir)) {
      try {
        fs.rmSync(testTempDir, { recursive: true, force: true });
      } catch {}
    }
    server.close();
  }

  console.log('\n========================================================');
  console.log('         PHASE 2 COMPREHENSIVE TEST REPORT              ');
  console.log('========================================================');

  const total = results.length;
  const passed = results.filter((r) => r.passed).length;
  const failed = total - passed;

  console.table(results);
  console.log(`TOTAL TESTS: ${total}`);
  console.log(`PASSED:      ${passed}`);
  console.log(`FAILED:      ${failed}`);

  if (failed > 0) {
    process.exit(1);
  } else {
    console.log('\n>>> ALL PHASE 2 MOCKED & LIVE CLOUD TESTS PASSED! <<<');
    process.exit(0);
  }
}

runPhase2Tests();
