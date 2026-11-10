const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const mongoose = require('mongoose');
const Project = require('../models/Project');
const { safeExtractZip } = require('../services/uploads/zipService');
const { detectProjectMetadata } = require('../services/detector/projectDetector');
const {
  isSupabaseConfigured,
  uploadProjectArchive,
  getSignedDownloadUrl,
  deleteProjectArchive
} = require('../services/storage/supabaseStorageService');
const { sanitizeErrorMessage } = require('../utils/workerAuth');

const isServerlessEnv = () =>
  Boolean(process.env.NETLIFY || process.env.AWS_LAMBDA_FUNCTION_NAME || process.env.LAMBDA_TASK_ROOT);

/**
 * Determine suitable persistent local directory (local development only)
 */
const resolveLocalExtractedDir = (projectId) => {
  const localBase = path.resolve(__dirname, '../uploads/projects');
  if (!fs.existsSync(localBase)) {
    fs.mkdirSync(localBase, { recursive: true });
  }
  return path.join(localBase, projectId.toString(), 'extracted');
};

/**
 * Clean up temporary path safely
 */
const safeRemovePath = (targetPath, isDir = false) => {
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
    console.warn(`[Cleanup Warning] Could not clean ${targetPath}: ${err.message}`);
  }
};

/**
 * @desc    Upload, validate, and store a project ZIP file (Supabase Storage + local fallback)
 * @route   POST /api/projects/:id/upload
 * @access  Private
 */
const uploadProjectZip = async (req, res) => {
  const { id } = req.params;
  const tempFilePath = req.file ? req.file.path : null;
  let stagingDir = null;
  let uploadedStorageKey = null;

  if (!mongoose.Types.ObjectId.isValid(id)) {
    safeRemovePath(tempFilePath, false);
    return res.status(400).json({
      status: 'fail',
      message: 'Invalid project ID format'
    });
  }

  try {
    const project = await Project.findById(id);

    if (!project) {
      safeRemovePath(tempFilePath, false);
      return res.status(404).json({
        status: 'fail',
        message: 'Project not found'
      });
    }

    if (!project.owner.equals(req.user._id)) {
      safeRemovePath(tempFilePath, false);
      return res.status(403).json({
        status: 'fail',
        message: 'Access denied. You do not own this project'
      });
    }

    if (!req.file) {
      return res.status(400).json({
        status: 'fail',
        message: 'No ZIP archive uploaded. Please attach a .zip file with field name "file" or "projectZip"'
      });
    }

    const serverless = isServerlessEnv();
    const supabaseReady = isSupabaseConfigured();

    if (serverless && !supabaseReady) {
      return res.status(503).json({
        status: 'error',
        message: 'Cloud archive storage is not configured for serverless deployment'
      });
    }

    // 1. Safely extract into an isolated temporary staging directory first
    // Prevents partial failure from corrupting any prior project state
    stagingDir = path.join(os.tmpdir(), `aegisor-stage-${project._id}-${crypto.randomBytes(4).toString('hex')}`);
    const extractResult = await safeExtractZip(tempFilePath, stagingDir);

    // 2. Automatically detect programming languages, manifests, frameworks
    const metadata = await detectProjectMetadata(stagingDir);

    // 3. Upload archive to Supabase private bucket if configured
    const previousStorageKey = project.storageKey || null;
    let newStorageKey = null;
    let storageBucket = project.storageBucket || 'project-archives';

    if (supabaseReady) {
      try {
        const uploadRes = await uploadProjectArchive(
          project._id.toString(),
          tempFilePath,
          req.file.originalname
        );
        newStorageKey = uploadRes.storageKey;
        storageBucket = uploadRes.bucket;
        uploadedStorageKey = newStorageKey;
      } catch (storageErr) {
        console.error(`[Supabase Storage Error] ${sanitizeErrorMessage(storageErr)}`);
        return res.status(502).json({
          status: 'error',
          message: `Cloud storage upload failed: ${sanitizeErrorMessage(storageErr)}`
        });
      }
    }

    // 4. In local development, mirror extracted tree to local workspace uploads folder
    let localTargetDir = null;
    if (!serverless) {
      try {
        localTargetDir = resolveLocalExtractedDir(project._id);
        await safeExtractZip(tempFilePath, localTargetDir);
      } catch (localErr) {
        console.warn(`[Local Staging Warning] ${localErr.message}`);
        localTargetDir = null;
      }
    }

    // 5. Update project metadata in MongoDB Atlas
    project.originalFileName = req.file.originalname;
    project.programmingLanguages = metadata.programmingLanguages;
    project.frameworks = metadata.frameworks;
    project.manifestFiles = metadata.manifestFiles;
    project.entryPoints = metadata.entryPoints;
    project.extractedPath = localTargetDir;
    project.fileCount = metadata.fileCount;
    project.totalLinesOfCode = metadata.totalLinesOfCode;
    project.storageKey = newStorageKey !== null ? newStorageKey : previousStorageKey;
    project.storageBucket = storageBucket;

    await project.save();

    // Commit succeeded: remove rollback marker and delete previous archive version if replaced
    uploadedStorageKey = null;
    if (supabaseReady && previousStorageKey && newStorageKey && previousStorageKey !== newStorageKey) {
      await deleteProjectArchive(previousStorageKey);
    }

    return res.status(200).json({
      status: 'success',
      message: 'ZIP archive uploaded and inspected successfully',
      data: {
        project: {
          _id: project._id,
          name: project.name,
          originalFileName: project.originalFileName,
          programmingLanguages: project.programmingLanguages,
          frameworks: project.frameworks,
          manifestFiles: project.manifestFiles,
          entryPoints: project.entryPoints,
          fileCount: project.fileCount,
          totalLinesOfCode: project.totalLinesOfCode,
          extractedFilesCount: extractResult.extractedCount,
          storageKey: project.storageKey,
          storageConfigured: supabaseReady
        }
      }
    });
  } catch (error) {
    // Roll back newly uploaded Supabase archive if MongoDB persistence failed
    if (uploadedStorageKey) {
      console.warn(`[Upload Rollback] Deleting orphaned Supabase object ${uploadedStorageKey}`);
      await deleteProjectArchive(uploadedStorageKey);
    }

    const safeMessage = sanitizeErrorMessage(error);
    console.error(`[AEGISOR Upload Error] ${safeMessage}`);

    const statusCode =
      safeMessage.includes('Security') || safeMessage.includes('ZIP') || safeMessage.includes('Invalid')
        ? 400
        : 500;

    return res.status(statusCode).json({
      status: statusCode === 400 ? 'fail' : 'error',
      message: safeMessage || 'Failed to process project archive'
    });
  } finally {
    // Always clean up temp ZIP and staging directory
    safeRemovePath(tempFilePath, false);
    safeRemovePath(stagingDir, true);
  }
};

/**
 * @desc    Generate a secure signed download URL for private archive
 * @route   GET /api/projects/:id/archive
 * @access  Private
 */
const getProjectArchiveDownload = async (req, res) => {
  const { id } = req.params;

  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({
      status: 'fail',
      message: 'Invalid project ID format'
    });
  }

  try {
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

    if (!project.storageKey && !project.extractedPath) {
      return res.status(404).json({
        status: 'fail',
        message: 'No archive has been uploaded for this project'
      });
    }

    if (isSupabaseConfigured() && project.storageKey) {
      const signedUrl = await getSignedDownloadUrl(project.storageKey, 120);
      return res.status(200).json({
        status: 'success',
        data: {
          mode: 'cloud',
          downloadUrl: signedUrl,
          expiresIn: 120,
          storageKey: project.storageKey,
          originalFileName: project.originalFileName
        }
      });
    }

    return res.status(200).json({
      status: 'success',
      data: {
        mode: 'local',
        originalFileName: project.originalFileName,
        extractedPath: project.extractedPath,
        message: 'Archive is stored locally in development mode'
      }
    });
  } catch (error) {
    console.error(`[AEGISOR Download Error] ${sanitizeErrorMessage(error)}`);
    return res.status(500).json({
      status: 'error',
      message: sanitizeErrorMessage(error) || 'Failed to retrieve archive download'
    });
  }
};

module.exports = {
  uploadProjectZip,
  getProjectArchiveDownload,
  resolveLocalExtractedDir
};
