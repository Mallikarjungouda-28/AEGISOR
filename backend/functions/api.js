const serverless = require('serverless-http');
const app = require('../app');
const connectDB = require('../config/db');

/**
 * Path normalization helper for Netlify serverless functions.
 * Maps both direct function calls (/.netlify/functions/api/*)
 * and redirected calls (/api/*) to the expected Express router paths.
 *
 * @param {string} rawPath
 * @returns {string}
 */
const normalizePath = (rawPath) => {
  if (!rawPath) return '/';

  // Strip Netlify internal function route prefix: /.netlify/functions/api
  let p = rawPath.replace(/^\/\.netlify\/functions\/api/, '');
  if (!p || p === '') return '/';

  // If redirected from /api/* to /:splat, ensure /api prefix is present for Express routes
  if (!p.startsWith('/api') && p !== '/') {
    p = '/api' + (p.startsWith('/') ? p : '/' + p);
  }

  return p;
};

const serverlessHandler = serverless(app, {
  binary: ['multipart/form-data', 'application/zip', 'application/pdf', 'application/octet-stream']
});

/**
 * Netlify Function Handler
 * Wraps Express application with serverless-http and handles MongoDB connection pooling
 */
const handler = async (event, context = {}) => {
  // Allow Lambda/Netlify to freeze background connection pools without waiting for event loop to empty
  if (context) {
    context.callbackWaitsForEmptyEventLoop = false;
  }

  // Ensure MongoDB Atlas connection is established or reused from cache
  await connectDB();

  // Normalize request path for Express routing
  const normalizedEvent = {
    ...event,
    path: normalizePath(event.path)
  };

  return serverlessHandler(normalizedEvent, context);
};

module.exports = { handler, normalizePath };

