const { createClient } = require('@supabase/supabase-js');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { sanitizeErrorMessage } = require('../../utils/workerAuth');

let supabaseClient = null;
let mockClientOverride = null;

/**
 * Allows injecting a mock client during isolated automated testing
 * Pass null to restore real Supabase client behavior
 * @param {object|null} mockClient
 */
const _setMockSupabaseClient = (mockClient) => {
  mockClientOverride = mockClient;
  if (!mockClient) {
    supabaseClient = null;
  }
};

/**
 * Returns true if Supabase Storage credentials are configured and non-placeholder
 * @returns {boolean}
 */
const isSupabaseConfigured = () => {
  if (mockClientOverride) return true;

  const url = (process.env.SUPABASE_URL || '').trim();
  const key = (process.env.SUPABASE_SECRET_KEY || '').trim();

  if (!url || !key) return false;
  if (!/^https?:\/\//i.test(url)) return false;
  if (url.includes('your-project-ref') || key.includes('your_supabase')) return false;

  return true;
};

/**
 * Get or initialize the Supabase client using backend secret key
 * Never logs credentials
 * @returns {object|null}
 */
const getSupabaseClient = () => {
  if (mockClientOverride) {
    return mockClientOverride;
  }

  if (!isSupabaseConfigured()) {
    return null;
  }

  if (!supabaseClient) {
    const supabaseUrl = process.env.SUPABASE_URL.trim();
    const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY.trim();

    supabaseClient = createClient(supabaseUrl, supabaseSecretKey, {
      auth: {
        persistSession: false,
        autoRefreshToken: false
      }
    });
  }

  return supabaseClient;
};

/**
 * Returns configured storage bucket name
 * @returns {string}
 */
const getStorageBucket = () => {
  return (process.env.SUPABASE_BUCKET || 'project-archives').trim();
};

/**
 * Validate storage object key against traversal attempts
 */
const validateStorageKey = (storageKey) => {
  if (!storageKey || typeof storageKey !== 'string') {
    throw new Error('Invalid storage object key');
  }
  if (storageKey.includes('..') || storageKey.startsWith('/') || storageKey.includes('\\')) {
    throw new Error('Security Alert: Illegal path characters in storage key');
  }
};

/**
 * Executes an async storage operation with bounded retry on transient failures
 */
const withRetry = async (operationFn, maxAttempts = 2) => {
  let lastErr;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await operationFn();
    } catch (err) {
      lastErr = err;
      const msg = (err.message || '').toLowerCase();
      // Do not retry deterministic auth/permission/missing errors
      const isNonRetryable =
        msg.includes('not configured') ||
        msg.includes('unauthorized') ||
        msg.includes('forbidden') ||
        msg.includes('not found') ||
        msg.includes('invalid') ||
        msg.includes('security alert');
      if (isNonRetryable || attempt === maxAttempts) {
        throw err;
      }
      await new Promise((r) => setTimeout(r, 300 * attempt));
    }
  }
  throw lastErr;
};

/**
 * Upload a project ZIP archive to private Supabase Storage
 * Generates a unique non-colliding storage object path
 *
 * @param {string} projectId - MongoDB Project ID
 * @param {string} localFilePath - Path to temporary uploaded zip file
 * @param {string} originalName - Original uploaded filename
 * @returns {Promise<{ storageKey: string, bucket: string, size: number }>}
 */
const uploadProjectArchive = async (projectId, localFilePath, originalName) => {
  const client = getSupabaseClient();
  if (!client) {
    throw new Error(
      'Supabase Storage is not configured. Set valid SUPABASE_URL and SUPABASE_SECRET_KEY in .env'
    );
  }

  if (!projectId || String(projectId).includes('..')) {
    throw new Error('Invalid project identifier for storage upload');
  }

  const bucket = getStorageBucket();
  const sanitizedName = path.basename(originalName || 'archive.zip').replace(/[^a-zA-Z0-9._-]/g, '_');
  const uniqueNonce = crypto.randomBytes(6).toString('hex');
  const storageKey = `projects/${projectId}/${Date.now()}-${uniqueNonce}_${sanitizedName}`;

  const fileBuffer = fs.readFileSync(localFilePath);
  const fileSize = fileBuffer.length;

  return withRetry(async () => {
    const { data, error } = await client.storage
      .from(bucket)
      .upload(storageKey, fileBuffer, {
        contentType: 'application/zip',
        upsert: false
      });

    if (error) {
      throw new Error(`Supabase upload error: ${sanitizeStorageErrorMessage(error)}`);
    }

    return {
      storageKey: data?.path || storageKey,
      bucket,
      size: fileSize
    };
  });
};

const sanitizeStorageErrorMessage = (error) => {
  return sanitizeErrorMessage(error?.message || 'Storage operation failed');
};

/**
 * Download a project ZIP archive from private Supabase Storage as a Buffer
 *
 * @param {string} storageKey - Path key inside bucket
 * @returns {Promise<Buffer>}
 */
const downloadProjectArchive = async (storageKey) => {
  const client = getSupabaseClient();
  if (!client) {
    throw new Error(
      'Supabase Storage is not configured. Set valid SUPABASE_URL and SUPABASE_SECRET_KEY in .env'
    );
  }

  validateStorageKey(storageKey);
  const bucket = getStorageBucket();

  return withRetry(async () => {
    const { data, error } = await client.storage.from(bucket).download(storageKey);

    if (error) {
      throw new Error(`Supabase download error: ${sanitizeStorageErrorMessage(error)}`);
    }

    if (!data) {
      throw new Error('Supabase download returned empty archive payload');
    }

    if (Buffer.isBuffer(data)) {
      return data;
    }

    const arrayBuffer = await data.arrayBuffer();
    return Buffer.from(arrayBuffer);
  });
};

/**
 * Generate a short-lived signed download URL for a private archive
 *
 * @param {string} storageKey - Path key inside bucket
 * @param {number} expiresInSeconds - Expiration time in seconds (default: 60)
 * @returns {Promise<string>}
 */
const getSignedDownloadUrl = async (storageKey, expiresInSeconds = 60) => {
  const client = getSupabaseClient();
  if (!client) {
    throw new Error(
      'Supabase Storage is not configured. Set valid SUPABASE_URL and SUPABASE_SECRET_KEY in .env'
    );
  }

  validateStorageKey(storageKey);
  const bucket = getStorageBucket();

  const { data, error } = await client.storage
    .from(bucket)
    .createSignedUrl(storageKey, expiresInSeconds);

  if (error || !data?.signedUrl) {
    throw new Error(`Failed to generate signed download URL: ${sanitizeStorageErrorMessage(error)}`);
  }

  return data.signedUrl;
};

/**
 * Delete a specific archive from Supabase Storage
 *
 * @param {string} storageKey - Path key inside bucket
 * @returns {Promise<boolean>}
 */
const deleteProjectArchive = async (storageKey) => {
  if (!storageKey) return false;

  const client = getSupabaseClient();
  if (!client) return false;

  validateStorageKey(storageKey);
  const bucket = getStorageBucket();

  try {
    const { error } = await client.storage.from(bucket).remove([storageKey]);
    if (error) {
      console.warn(`[Supabase Storage Warning] Could not delete ${storageKey}: ${sanitizeStorageErrorMessage(error)}`);
      return false;
    }
    return true;
  } catch (err) {
    console.warn(`[Supabase Storage Warning] Deletion exception: ${sanitizeStorageErrorMessage(err)}`);
    return false;
  }
};

/**
 * Delete all archives stored under a project's prefix
 *
 * @param {string} projectId
 * @returns {Promise<number>} Number of deleted objects
 */
const deleteProjectFolder = async (projectId) => {
  if (!projectId || String(projectId).includes('..')) return 0;

  const client = getSupabaseClient();
  if (!client) return 0;

  const bucket = getStorageBucket();
  const prefix = `projects/${projectId}`;

  try {
    const { data: fileList, error: listError } = await client.storage
      .from(bucket)
      .list(prefix);

    if (listError || !fileList || fileList.length === 0) {
      return 0;
    }

    const pathsToDelete = fileList.map((f) => `${prefix}/${f.name}`);
    const { error: removeError } = await client.storage.from(bucket).remove(pathsToDelete);

    if (removeError) {
      console.warn(
        `[Supabase Storage Warning] Could not remove folder ${prefix}: ${sanitizeStorageErrorMessage(removeError)}`
      );
      return 0;
    }

    return pathsToDelete.length;
  } catch (err) {
    console.warn(`[Supabase Storage Warning] Folder purge exception: ${sanitizeStorageErrorMessage(err)}`);
    return 0;
  }
};

module.exports = {
  _setMockSupabaseClient,
  isSupabaseConfigured,
  getSupabaseClient,
  getStorageBucket,
  uploadProjectArchive,
  downloadProjectArchive,
  getSignedDownloadUrl,
  deleteProjectArchive,
  deleteProjectFolder
};
