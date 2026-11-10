const express = require('express');
const router = express.Router();
const { getDashboardOverview } = require('../controllers/dashboardController');
const { protect } = require('../middleware/authMiddleware');

router.use(protect);

router.get('/overview', getDashboardOverview);

module.exports = router;

