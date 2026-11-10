const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const Project = require('../../models/Project');
const Scan = require('../../models/Scan');
const Vulnerability = require('../../models/Vulnerability');
const connectDB = require('../../config/db');
const { safeExtractZip } = require('../uploads/zipService');
const { orchestrateScan } = require('./scannerOrchestrator');
const { generateScanSummary, isGeminiConfigured } = require('../ai/geminiService');
const {
  isSupabaseConfigured,
  downloadProjectArchive
} = require('../storage/supabaseStorageService');
const { sanitizeErrorMessage } = require('../../utils/workerAuth');

/**
 * Safely remove temporary file or directory without throwing
 */
const safeRemove = (targetPath, isDir = false) => {
  if (!targetPath) return;
  try {
    if (fs.existsSync(targetPath)) {
      if (isDir) {
        fs.rmSync(targetPath, { recursive: true, force: true });
      } else {
        fs.unlinkSync(targetPath);
      }
    }
  } catch (err) {
    console.warn(`[Temp Cleanup Warning] ${targetPath}: ${err.message}`);
  }
};

/**
 * Universal idempotent scan execution pipeline
 * Reused by local async dispatcher and Netlify scan-background function
 *
 * Prevents duplicate findings on repeated invocations via atomic status transition
 * from 'pending' to 'processing'.
 *
 * @param {object} params
 * @param {string} params.scanId - Scan Document ID
 * @param {string} params.projectId - Project Document ID
 * @param {string} [params.targetDir] - Optional pre-extracted local folder
 * @param {Array<string>} [params.languages] - Optional detected languages
 * @returns {Promise<object>} Completed or deduplicated scan document
 */
const runScanPipeline = async ({ scanId, projectId, targetDir, languages = [] }) => {
  // Ensure database connection is active (critical in serverless invocations)
  await connectDB();

  // Atomically transition from 'pending' -> 'processing' to lock against duplicate invocations
  const scan = await Scan.findOneAndUpdate(
    { _id: scanId, status: 'pending' },
    { $set: { status: 'processing', scanStartedAt: new Date() } },
    { returnDocument: 'after' }
  );

  if (!scan) {
    const existing = await Scan.findById(scanId);
    if (!existing) {
      throw new Error(`Scan ${scanId} not found`);
    }

    // Repeated invocation guard: if already processing or completed, exit cleanly without duplicating
    if (existing.status === 'processing' || existing.status === 'completed') {
      console.log(
        `[Scan Pipeline] Scan ${scanId} is already '${existing.status}'. Skipping duplicate execution.`
      );
      return existing;
    }

    // Scan was previously failed
    throw new Error(`Scan ${scanId} is in '${existing.status}' state and cannot be executed again`);
  }

  const project = await Project.findById(projectId);
  if (!project) {
    scan.status = 'failed';
    scan.errorMessage = `Project ${projectId} not found`;
    scan.scanCompletedAt = new Date();
    await scan.save();
    throw new Error(`Project ${projectId} not found`);
  }

  let scanDir = targetDir || project.extractedPath;
  let tempZipPath = null;
  let tempExtractDir = null;

  try {
    // 1. Resolve source code directory
    // Prefer persistent local directory in dev; retrieve from private Supabase Storage on serverless or when missing locally
    const hasValidLocalDir = scanDir && fs.existsSync(scanDir);

    if (!hasValidLocalDir) {
      if (!project.storageKey) {
        throw new Error(
          'Project archive not found on local disk and no Supabase Storage key is registered'
        );
      }

      if (!isSupabaseConfigured()) {
        throw new Error(
          'Archive is stored in Supabase Storage, but SUPABASE_URL / SUPABASE_SECRET_KEY are not configured'
        );
      }

      const nonce = crypto.randomBytes(4).toString('hex');
      const zipBuffer = await downloadProjectArchive(project.storageKey);

      tempZipPath = path.join(os.tmpdir(), `aegisor-scan-${scanId}-${nonce}.zip`);
      fs.writeFileSync(tempZipPath, zipBuffer);

      tempExtractDir = path.join(os.tmpdir(), 'aegisor-scans', `${scanId}-${nonce}`);
      await safeExtractZip(tempZipPath, tempExtractDir);

      // Clean temporary ZIP immediately once safely extracted to save /tmp space
      safeRemove(tempZipPath, false);
      tempZipPath = null;

      scanDir = tempExtractDir;
    }

    const effectiveLanguages =
      languages.length > 0 ? languages : project.programmingLanguages || [];

    // 2. Run scanner orchestrator across built-in engine and available adapters
    const scanResult = await orchestrateScan(scanDir, effectiveLanguages);

    // 3. Ensure idempotent persistence: remove any stale findings for this scanId prior to insert
    await Vulnerability.deleteMany({ scan: scanId });

    const createdVulns = [];
    if (scanResult.findings.length > 0) {
      const vulnDocs = scanResult.findings.map((f) => ({
        project: projectId,
        scan: scanId,
        title: f.title,
        description: f.description,
        severity: f.severity,
        affectedFile: f.affectedFile,
        lineNumber: f.lineNumber,
        cwe: f.cwe,
        detectionSource: f.detectionSource,
        codeSnippet: f.codeSnippet,
        recommendation: f.recommendation
      }));

      const inserted = await Vulnerability.insertMany(vulnDocs);
      createdVulns.push(...inserted);
    }

    // 4. Generate AI executive summary if Gemini is configured
    let aiSummaryText = null;
    if (isGeminiConfigured()) {
      try {
        aiSummaryText = await generateScanSummary(scanResult, project, createdVulns);
      } catch (aiErr) {
        console.warn(`[AI Summary Warning] ${sanitizeErrorMessage(aiErr)}`);
      }
    }

    // 5. Update scan record to completed
    scan.status = 'completed';
    scan.securityScore = scanResult.securityScore;
    scan.totalVulnerabilities = scanResult.totalVulnerabilities;
    scan.severityBreakdown = scanResult.severityBreakdown;
    scan.scannersRun = scanResult.scannersRun;
    scan.scannersUnavailable = scanResult.scannersUnavailable;
    scan.scannersFailed = scanResult.scannersFailed;
    scan.aiSummary = aiSummaryText;
    scan.errorMessage = null;
    scan.scanCompletedAt = new Date();
    await scan.save();

    // 6. Update parent project summary metrics
    await Project.findByIdAndUpdate(projectId, {
      lastScanDate: new Date(),
      latestSecurityScore: scanResult.securityScore
    });

    return scan;
  } catch (error) {
    const safeError = sanitizeErrorMessage(error);
    console.error(`[AEGISOR Scan Pipeline Error] ${safeError}`);
    scan.status = 'failed';
    scan.errorMessage = safeError;
    scan.scanCompletedAt = new Date();
    await scan.save();
    throw new Error(safeError);
  } finally {
    // 7. Always cleanup ephemeral files in os.tmpdir()
    safeRemove(tempZipPath, false);
    safeRemove(tempExtractDir, true);
  }
};

module.exports = { runScanPipeline };
