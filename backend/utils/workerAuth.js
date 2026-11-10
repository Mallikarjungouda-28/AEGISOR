const crypto = require('crypto');

const MAX_SIGNATURE_AGE_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Retrieve shared secret for signing internal background worker calls
 * Never returns or logs the secret externally
 */
const getWorkerSecret = () => {
  const secret = process.env.INTERNAL_WORKER_SECRET || process.env.JWT_SECRET;
  if (!secret) {
    throw new Error('Worker authentication secret is not configured');
  }
  return secret;
};

/**
 * Generate HMAC-SHA256 authentication headers for background function invocation
 * Only signs scanId, projectId, and timestamp (never includes secrets in payload)
 *
 * @param {string} scanId
 * @param {string} projectId
 * @param {number} [timestamp]
 * @returns {{ 'x-aegisor-worker-timestamp': string, 'x-aegisor-worker-signature': string }}
 */
const signWorkerPayload = (scanId, projectId, timestamp = Date.now()) => {
  const secret = getWorkerSecret();
  const data = `${timestamp}:${scanId}:${projectId}`;
  const signature = crypto.createHmac('sha256', secret).update(data).digest('hex');

  return {
    'x-aegisor-worker-timestamp': String(timestamp),
    'x-aegisor-worker-signature': signature
  };
};

/**
 * Constant-time verification of background worker headers
 *
 * @param {object} headers
 * @param {string} scanId
 * @param {string} projectId
 * @returns {{ valid: boolean, reason?: string }}
 */
const verifyWorkerSignature = (headers = {}, scanId, projectId) => {
  try {
    // Normalize header names to lowercase
    const normalizedHeaders = {};
    for (const [k, v] of Object.entries(headers)) {
      normalizedHeaders[k.toLowerCase()] = v;
    }

    const timestampStr = normalizedHeaders['x-aegisor-worker-timestamp'];
    const receivedSig = normalizedHeaders['x-aegisor-worker-signature'];

    if (!timestampStr || !receivedSig) {
      return { valid: false, reason: 'Missing worker authentication headers' };
    }

    const timestamp = Number(timestampStr);
    if (!Number.isFinite(timestamp) || Math.abs(Date.now() - timestamp) > MAX_SIGNATURE_AGE_MS) {
      return { valid: false, reason: 'Worker request signature expired or invalid timestamp' };
    }

    const secret = getWorkerSecret();
    const expectedData = `${timestamp}:${scanId}:${projectId}`;
    const expectedSig = crypto.createHmac('sha256', secret).update(expectedData).digest('hex');

    const recvBuf = Buffer.from(String(receivedSig), 'hex');
    const expBuf = Buffer.from(expectedSig, 'hex');

    if (recvBuf.length !== expBuf.length || !crypto.timingSafeEqual(recvBuf, expBuf)) {
      return { valid: false, reason: 'Invalid worker signature' };
    }

    return { valid: true };
  } catch (err) {
    return { valid: false, reason: 'Signature verification failed' };
  }
};

/**
 * Redact environment secrets and credential patterns from error messages
 *
 * @param {Error|string} err
 * @returns {string}
 */
const sanitizeErrorMessage = (err) => {
  let msg = typeof err === 'string' ? err : err?.message || 'Unknown error';

  // Redact common credential patterns
  msg = msg
    .replace(/(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g, '[REDACTED_AWS_KEY]')
    .replace(/gh[pousr]_[A-Za-z0-9_]{36,255}/g, '[REDACTED_GITHUB_TOKEN]')
    .replace(/(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql):\/\/[^@\s]+@[^\s"']+/g, '[REDACTED_DB_URI]')
    .replace(/Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi, 'Bearer [REDACTED]')
    .replace(/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, '[REDACTED_JWT]')
    .replace(/sb_(?:secret|publishable)_[A-Za-z0-9_-]+/g, '[REDACTED_SUPABASE_KEY]');

  // Explicitly scrub runtime secret values if present in message
  const sensitiveEnvKeys = [
    'MONGODB_URI',
    'JWT_SECRET',
    'GEMINI_API_KEY',
    'SUPABASE_SECRET_KEY',
    'SUPABASE_URL',
    'INTERNAL_WORKER_SECRET'
  ];

  for (const key of sensitiveEnvKeys) {
    const val = process.env[key];
    if (val && val.length > 6 && msg.includes(val)) {
      msg = msg.split(val).join(`[REDACTED_${key}]`);
    }
  }

  return msg;
};

module.exports = {
  signWorkerPayload,
  verifyWorkerSignature,
  sanitizeErrorMessage
};

