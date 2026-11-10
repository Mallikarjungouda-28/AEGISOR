const express = require('express');
const router = express.Router();
const {
  getScanById,
  getScanStatus,
  getScanResults,
  downloadScanReport
} = require('../controllers/scanController');
const { protect } = require('../middleware/authMiddleware');

router.use(protect);

router.get('/:id', getScanById);
router.get('/:id/status', getScanStatus);
router.get('/:id/results', getScanResults);
router.get('/:id/report', downloadScanReport);

module.exports = router;

