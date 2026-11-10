const Project = require('../models/Project');
const Scan = require('../models/Scan');
const Vulnerability = require('../models/Vulnerability');

/**
 * @desc    Get dashboard overview metrics, scores, and activity
 * @route   GET /api/dashboard/overview
 * @access  Private
 */
const getDashboardOverview = async (req, res) => {
  try {
    const userId = req.user._id;

    // 1. Projects metrics
    const userProjects = await Project.find({ owner: userId }).select('_id name createdAt latestSecurityScore');
    const totalProjects = userProjects.length;
    const projectIds = userProjects.map((p) => p._id);

    // 2. Scans metrics
    const [totalScans, completedScans, pendingScans, processingScans, failedScans] = await Promise.all([
      Scan.countDocuments({ initiatedBy: userId }),
      Scan.countDocuments({ initiatedBy: userId, status: 'completed' }),
      Scan.countDocuments({ initiatedBy: userId, status: 'pending' }),
      Scan.countDocuments({ initiatedBy: userId, status: 'processing' }),
      Scan.countDocuments({ initiatedBy: userId, status: 'failed' })
    ]);

    // 3. Average security score across completed scans
    const completedScansList = await Scan.find({
      initiatedBy: userId,
      status: 'completed',
      securityScore: { $ne: null }
    }).select('securityScore');

    let averageSecurityScore = null;
    if (completedScansList.length > 0) {
      const sum = completedScansList.reduce((acc, s) => acc + s.securityScore, 0);
      averageSecurityScore = Math.round(sum / completedScansList.length);
    }

    // 4. Vulnerabilities metrics across all user projects
    const severityDistribution = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      informational: 0
    };

    let totalVulnerabilities = 0;

    if (projectIds.length > 0) {
      const vulnStats = await Vulnerability.aggregate([
        { $match: { project: { $in: projectIds } } },
        { $group: { _id: '$severity', count: { $sum: 1 } } }
      ]);

      for (const stat of vulnStats) {
        if (severityDistribution[stat._id] !== undefined) {
          severityDistribution[stat._id] = stat.count;
          totalVulnerabilities += stat.count;
        }
      }
    }

    // 5. Latest scan info
    const latestScan = await Scan.findOne({ initiatedBy: userId })
      .sort({ createdAt: -1 })
      .populate('project', 'name originalFileName');

    // 6. Recent activity (last 5 scans)
    const recentScans = await Scan.find({ initiatedBy: userId })
      .sort({ createdAt: -1 })
      .limit(5)
      .populate('project', 'name');

    return res.status(200).json({
      status: 'success',
      data: {
        metrics: {
          totalProjects,
          totalScans,
          completedScans,
          pendingScans,
          processingScans,
          failedScans,
          averageSecurityScore,
          totalVulnerabilities,
          severityDistribution
        },
        latestScan,
        recentActivity: {
          recentScans
        }
      }
    });
  } catch (error) {
    console.error(`[AEGISOR Dashboard Error] Overview: ${error.message}`);
    return res.status(500).json({
      status: 'error',
      message: 'Internal server error generating dashboard overview'
    });
  }
};

module.exports = {
  getDashboardOverview
};

