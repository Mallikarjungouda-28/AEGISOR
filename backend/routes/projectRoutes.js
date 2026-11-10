const express = require('express');
const router = express.Router();
const {
  createProject,
  getProjects,
  getProjectById,
  updateProject,
  deleteProject
} = require('../controllers/projectController');
const {
  uploadProjectZip,
  getProjectArchiveDownload
} = require('../controllers/uploadController');
const { createScan, getProjectScans } = require('../controllers/scanController');
const { getProjectVulnerabilities } = require('../controllers/vulnerabilityController');
const { protect } = require('../middleware/authMiddleware');
const { uploadZip } = require('../middleware/uploadMiddleware');

// All project routes require authentication
router.use(protect);

router.route('/')
  .post(createProject)
  .get(getProjects);

router.route('/:id')
  .get(getProjectById)
  .put(updateProject)
  .delete(deleteProject);

// ZIP file upload endpoint (accepts 'file' or 'projectZip')
router.post('/:id/upload', (req, res, next) => {
  uploadZip('file')(req, res, (err) => {
    if (err) return next(err);
    if (!req.file) {
      return uploadZip('projectZip')(req, res, next);
    }
    next();
  });
}, uploadProjectZip);

// Secure private archive download / signed URL endpoint
router.get('/:id/archive', getProjectArchiveDownload);

// Scans for project
router.route('/:id/scans')
  .post(createScan)
  .get(getProjectScans);

// Vulnerabilities for project
router.get('/:id/vulnerabilities', getProjectVulnerabilities);

module.exports = router;
