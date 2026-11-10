const mongoose = require('mongoose');
const fs = require('fs');
const Project = require('../models/Project');
const Scan = require('../models/Scan');
const Vulnerability = require('../models/Vulnerability');
const { runScanPipeline } = require('../services/scanners/scanExecutionService');
const { generatePdfReport } = require('../services/reports/pdfReportService');
const { signWorkerPayload, sanitizeErrorMessage } = require('../utils/workerAuth');

// Maximum duration before a serverless background scan is reconciled as stale/failed (16 mins)
const STALE_SCAN_TIMEOUT_MS = 16 * 60 * 1000;

/**
 * Reconciles scans stuck in 'pending' or 'processing' past the serverless execution ceiling
 * @param {object} scan
 */
const reconcileStaleScan = async (scan) => {
  if (!scan || (scan.status !== 'pending' && scan.status !== 'processing')) {
    return scan;
  }

  const referenceTime = scan.scanStartedAt || scan.createdAt;
  if (referenceTime && Date.now() - new Date(referenceTime).getTime() > STALE_SCAN_TIMEOUT_MS) {
    scan.status = 'failed';
    scan.errorMessage =
      'Scan timed out after exceeding background worker execution limits. Please retry the scan.';
    scan.scanCompletedAt = new Date();
    await scan.save();
  }

  return scan;
};

/**
 * @desc    Initiate a new audit scan for a project
 * @route   POST /api/projects/:id/scans
 * @access  Private
 */
const createScan = async (req, res) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid project ID format'
      });
    }

    const project = await Project.findById(id);

    if (!project) {
      return res.status(404).json({
        status: 'fail',
        message: 'Project not found'
      });
    }

    if (!project.owner.equals(req.user._id)) {
      return res.status(403).json({
        status: 'fail',
        message: 'Access denied. You do not own this project'
      });
    }

    // Check if project has uploaded source files (on disk or in Supabase Storage)
    const hasLocalArchive = project.extractedPath && fs.existsSync(project.extractedPath);
    const hasCloudArchive = Boolean(project.storageKey);

    if (!hasLocalArchive && !hasCloudArchive) {
      return res.status(400).json({
        status: 'fail',
        message: 'Cannot initiate scan: No source code uploaded yet. Please upload a project ZIP archive first.'
      });
    }

    // Create scan record in pending state
    const scan = await Scan.create({
      project: project._id,
      initiatedBy: req.user._id,
      status: 'pending',
      scanStartedAt: new Date()
    });

    // Determine execution environment: Netlify Background Function or local setImmediate
    const isNetlify = Boolean(process.env.NETLIFY || process.env.AWS_LAMBDA_FUNCTION_NAME);
    const siteUrl = (process.env.URL || process.env.DEPLOY_PRIME_URL || '').replace(/\/+$/, '');

    if (isNetlify) {
      if (!siteUrl) {
        scan.status = 'failed';
        scan.errorMessage = 'Serverless site URL is unavailable to dispatch background scanner';
        scan.scanCompletedAt = new Date();
        await scan.save();
        return res.status(500).json({
          status: 'error',
          message: scan.errorMessage
        });
      }

      // Sign payload with internal HMAC secret (never exposes keys)
      const workerHeaders = signWorkerPayload(scan._id.toString(), project._id.toString());

      try {
        const bgResponse = await fetch(`${siteUrl}/.netlify/functions/scan-background`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...workerHeaders
          },
          body: JSON.stringify({ scanId: scan._id.toString(), projectId: project._id.toString() }),
          signal: AbortSignal.timeout(8000)
        });

        if (!bgResponse.ok) {
          throw new Error(`Background scanner dispatch failed with HTTP ${bgResponse.status}`);
        }
      } catch (triggerErr) {
        const safeErr = sanitizeErrorMessage(triggerErr);
        console.error(`[Background Trigger Error] ${safeErr}`);
        scan.status = 'failed';
        scan.errorMessage = `Failed to invoke background scanner: ${safeErr}`;
        scan.scanCompletedAt = new Date();
        await scan.save();

        return res.status(502).json({
          status: 'error',
          message: scan.errorMessage
        });
      }
    } else {
      // Local development or test execution: run asynchronously via event loop
      setImmediate(() => {
        runScanPipeline({
          scanId: scan._id,
          projectId: project._id,
          targetDir: project.extractedPath,
          languages: project.programmingLanguages || []
        }).catch((err) => console.error(`[Scan Error] ${sanitizeErrorMessage(err)}`));
      });
    }

    return res.status(202).json({
      status: 'success',
      message: 'Audit scan initiated successfully. Processing in background.',
      data: {
        scan: {
          _id: scan._id,
          project: scan.project,
          status: scan.status,
          initiatedBy: scan.initiatedBy,
          createdAt: scan.createdAt
        }
      }
    });
  } catch (error) {
    console.error(`[AEGISOR Scan Error] Create: ${error.message}`);
    return res.status(500).json({
      status: 'error',
      message: 'Internal server error initiating scan'
    });
  }
};

/**
 * @desc    Get all scans for a specific project
 * @route   GET /api/projects/:id/scans
 * @access  Private
 */
const getProjectScans = async (req, res) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid project ID format'
      });
    }

    const project = await Project.findById(id);

    if (!project) {
      return res.status(404).json({
        status: 'fail',
        message: 'Project not found'
      });
    }

    if (!project.owner.equals(req.user._id)) {
      return res.status(403).json({
        status: 'fail',
        message: 'Access denied. You do not own this project'
      });
    }

    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 10));
    const skip = (page - 1) * limit;

    const query = { project: project._id };

    const [total, scans] = await Promise.all([
      Scan.countDocuments(query),
      Scan.find(query).sort({ createdAt: -1 }).skip(skip).limit(limit)
    ]);

    return res.status(200).json({
      status: 'success',
      data: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
        scans
      }
    });
  } catch (error) {
    console.error(`[AEGISOR Scan Error] GetProjectScans: ${error.message}`);
    return res.status(500).json({
      status: 'error',
      message: 'Internal server error retrieving scans'
    });
  }
};

/**
 * @desc    Get details for an individual scan
 * @route   GET /api/scans/:id
 * @access  Private
 */
const getScanById = async (req, res) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid scan ID format'
      });
    }

    const scan = await Scan.findById(id).populate('project', 'name owner originalFileName');

    if (!scan) {
      return res.status(404).json({
        status: 'fail',
        message: 'Scan not found'
      });
    }

    // Verify ownership via project owner or initiator
    if (!scan.initiatedBy.equals(req.user._id) && !scan.project.owner.equals(req.user._id)) {
      return res.status(403).json({
        status: 'fail',
        message: 'Access denied. You do not have permission to view this scan'
      });
    }

    await reconcileStaleScan(scan);

    return res.status(200).json({
      status: 'success',
      data: { scan }
    });
  } catch (error) {
    console.error(`[AEGISOR Scan Error] GetScanById: ${error.message}`);
    return res.status(500).json({
      status: 'error',
      message: 'Internal server error retrieving scan'
    });
  }
};

/**
 * @desc    Lightweight scan status endpoint for frontend polling
 * @route   GET /api/scans/:id/status
 * @access  Private
 */
const getScanStatus = async (req, res) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid scan ID format'
      });
    }

    const scan = await Scan.findById(id).populate('project', 'owner');

    if (!scan) {
      return res.status(404).json({
        status: 'fail',
        message: 'Scan not found'
      });
    }

    if (!scan.initiatedBy.equals(req.user._id) && !scan.project.owner.equals(req.user._id)) {
      return res.status(403).json({
        status: 'fail',
        message: 'Access denied. You do not have permission to view this scan status'
      });
    }

    await reconcileStaleScan(scan);

    return res.status(200).json({
      status: 'success',
      data: {
        scanId: scan._id,
        projectId: scan.project._id,
        scanStatus: scan.status,
        securityScore: scan.securityScore,
        totalVulnerabilities: scan.totalVulnerabilities,
        errorMessage: scan.errorMessage || null,
        scanStartedAt: scan.scanStartedAt,
        scanCompletedAt: scan.scanCompletedAt
      }
    });
  } catch (error) {
    console.error(`[AEGISOR Scan Error] GetScanStatus: ${error.message}`);
    return res.status(500).json({
      status: 'error',
      message: 'Internal server error retrieving scan status'
    });
  }
};

/**
 * @desc    Get all vulnerabilities discovered in a specific scan
 * @route   GET /api/scans/:id/results
 * @access  Private
 */
const getScanResults = async (req, res) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid scan ID format'
      });
    }

    const scan = await Scan.findById(id).populate('project', 'name owner');

    if (!scan) {
      return res.status(404).json({
        status: 'fail',
        message: 'Scan not found'
      });
    }

    if (!scan.initiatedBy.equals(req.user._id) && !scan.project.owner.equals(req.user._id)) {
      return res.status(403).json({
        status: 'fail',
        message: 'Access denied. You do not have permission to view these scan results'
      });
    }

    const vulnerabilities = await Vulnerability.find({ scan: scan._id }).sort({
      severity: 1,
      createdAt: -1
    });

    return res.status(200).json({
      status: 'success',
      data: {
        scanId: scan._id,
        project: scan.project,
        totalFindings: vulnerabilities.length,
        securityScore: scan.securityScore,
        severityBreakdown: scan.severityBreakdown,
        vulnerabilities
      }
    });
  } catch (error) {
    console.error(`[AEGISOR Scan Error] GetScanResults: ${error.message}`);
    return res.status(500).json({
      status: 'error',
      message: 'Internal server error retrieving scan results'
    });
  }
};

/**
 * @desc    Download professional PDF audit report for a scan
 * @route   GET /api/scans/:id/report
 * @access  Private
 */
const downloadScanReport = async (req, res) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Invalid scan ID format'
      });
    }

    const scan = await Scan.findById(id);
    if (!scan) {
      return res.status(404).json({
        status: 'fail',
        message: 'Scan not found'
      });
    }

    const project = await Project.findById(scan.project);
    if (!project || !project.owner.equals(req.user._id)) {
      return res.status(403).json({
        status: 'fail',
        message: 'Access denied. You do not own this project report'
      });
    }

    const vulnerabilities = await Vulnerability.find({ scan: scan._id }).sort({ severity: 1 });

    const safeFilename = `${project.name.replace(/[^a-zA-Z0-9-_]/g, '_')}_Scan_${scan._id}.pdf`;

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${safeFilename}"`);

    generatePdfReport(scan, project, vulnerabilities, res);
  } catch (error) {
    console.error(`[AEGISOR Report Error] ${error.message}`);
    return res.status(500).json({
      status: 'error',
      message: 'Internal server error generating PDF report'
    });
  }
};

module.exports = {
  createScan,
  getProjectScans,
  getScanById,
  getScanStatus,
  getScanResults,
  downloadScanReport
};

