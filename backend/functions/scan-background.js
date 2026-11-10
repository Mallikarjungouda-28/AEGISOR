const mongoose = require('mongoose');
const { runScanPipeline } = require('../services/scanners/scanExecutionService');
const connectDB = require('../config/db');
const { verifyWorkerSignature, sanitizeErrorMessage } = require('../utils/workerAuth');

/**
 * Netlify Background Function for Asynchronous Security Scanning
 *
 * Limits & Architecture Notes:
 * - Suffix "-background" enables Netlify's asynchronous background runtime (up to 15 min limit).
 * - Netlify immediately returns HTTP 202 Accepted to callers before awaiting handler execution.
 * - Ephemeral storage (/tmp) has container-scoped lifetime; all temp files are cleaned in finally blocks.
 * - Accepts only minimal identifiers (scanId, projectId) authenticated by an HMAC-SHA256 worker signature.
 *
 * @param {object} event
 * @param {object} context
 */
const handler = async (event = {}, context = {}) => {
  if (context) {
    context.callbackWaitsForEmptyEventLoop = false;
  }

  try {
    let payload = {};
    if (event.body) {
      payload = typeof event.body === 'string' ? JSON.parse(event.body) : event.body;
    }

    const { scanId, projectId } = payload || {};

    if (!scanId || !projectId) {
      return {
        statusCode: 400,
        body: JSON.stringify({
          status: 'fail',
          message: 'Missing scanId or projectId in background invocation payload'
        })
      };
    }

    if (!mongoose.Types.ObjectId.isValid(scanId) || !mongoose.Types.ObjectId.isValid(projectId)) {
      return {
        statusCode: 400,
        body: JSON.stringify({
          status: 'fail',
          message: 'Invalid scanId or projectId format'
        })
      };
    }

    // Enforce internal worker HMAC signature to prevent unauthenticated invocations
    const verification = verifyWorkerSignature(event.headers || {}, String(scanId), String(projectId));
    if (!verification.valid) {
      console.warn(`[Scan Background Auth Denied] ${verification.reason} (scanId=${scanId})`);
      return {
        statusCode: 401,
        body: JSON.stringify({
          status: 'fail',
          message: verification.reason || 'Unauthorized background worker invocation'
        })
      };
    }

    // Connect to MongoDB Atlas (reuses warm connection pool if present)
    await connectDB();

    console.log(`[Scan Background] Processing scanId=${scanId}, projectId=${projectId}`);
    const scanDoc = await runScanPipeline({ scanId, projectId });
    console.log(
      `[Scan Background] Finished scanId=${scanId}, status=${scanDoc.status}, score=${scanDoc.securityScore}`
    );

    return {
      statusCode: 200,
      body: JSON.stringify({
        status: 'success',
        scanId: scanDoc._id,
        scanStatus: scanDoc.status,
        securityScore: scanDoc.securityScore,
        totalVulnerabilities: scanDoc.totalVulnerabilities
      })
    };
  } catch (error) {
    const safeMsg = sanitizeErrorMessage(error);
    console.error(`[Scan Background Failed] ${safeMsg}`);
    return {
      statusCode: 500,
      body: JSON.stringify({
        status: 'error',
        message: safeMsg
      })
    };
  }
};

module.exports = { handler };
