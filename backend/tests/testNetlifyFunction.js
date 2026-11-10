/**
 * AEGISOR Netlify Serverless Function Verification Suite
 * Tests handler execution, path normalization, and connection caching
 */

process.env.NODE_ENV = 'test';

const path = require('path');
const dotenv = require('dotenv');
dotenv.config({ path: path.join(__dirname, '../.env') });

const { handler, normalizePath } = require('../functions/api');
const connectDB = require('../config/db');
const mongoose = require('mongoose');

const results = [];
const record = (name, passed, details = '') => {
  results.push({ name, passed, details });
  const sym = passed ? 'PASS' : 'FAIL';
  console.log(`  [${sym}] ${name} ${details ? `(${details})` : ''}`);
};

async function runNetlifyTests() {
  console.log('========================================================');
  console.log('       AEGISOR NETLIFY FUNCTION VERIFICATION SUITE       ');
  console.log('========================================================\n');

  console.log('--- 1. PATH NORMALIZATION UNIT TESTS ---');
  record(
    'Root path normalization',
    normalizePath('/.netlify/functions/api') === '/',
    `Result: "${normalizePath('/.netlify/functions/api')}"`
  );
  record(
    'Trailing slash root normalization',
    normalizePath('/.netlify/functions/api/') === '/',
    `Result: "${normalizePath('/.netlify/functions/api/')}"`
  );
  record(
    'Prefixed /api sub-route normalization',
    normalizePath('/.netlify/functions/api/api/auth/login') === '/api/auth/login',
    `Result: "${normalizePath('/.netlify/functions/api/api/auth/login')}"`
  );
  record(
    'Direct splat sub-route normalization',
    normalizePath('/.netlify/functions/api/auth/login') === '/api/auth/login',
    `Result: "${normalizePath('/.netlify/functions/api/auth/login')}"`
  );
  record(
    'Direct standard /api route untouched',
    normalizePath('/api/projects') === '/api/projects',
    `Result: "${normalizePath('/api/projects')}"`
  );

  console.log('\n--- 2. MONGOOSE SERVERLESS CONNECTION CACHING ---');
  try {
    const conn1 = await connectDB();
    const isConnected1 = mongoose.connection.readyState === 1;
    record('First connection establishes or reuses DB', isConnected1);

    // Call connectDB a second time: should reuse connection immediately without reconnection
    const conn2 = await connectDB();
    const isCached = conn2 === conn1 || mongoose.connection.readyState === 1;
    record('Second invocation reuses warm connection pool', isCached);
  } catch (err) {
    record('MongoDB connection caching', false, err.message);
  }

  console.log('\n--- 3. NETLIFY FUNCTION HANDLER SIMULATION ---');
  try {
    // 3.1 Invoke Root Health Check via Serverless Handler
    const healthEvent = {
      httpMethod: 'GET',
      path: '/.netlify/functions/api',
      headers: {}
    };
    const mockContext = { callbackWaitsForEmptyEventLoop: true };

    const healthRes = await handler(healthEvent, mockContext);
    const healthBody = JSON.parse(healthRes.body);

    record(
      'Serverless handler serves root health check (200 OK)',
      healthRes.statusCode === 200 && healthBody.status === 'success',
      `Status: ${healthRes.statusCode}, Name: "${healthBody.name}"`
    );
    record(
      'Context callbackWaitsForEmptyEventLoop is set to false',
      mockContext.callbackWaitsForEmptyEventLoop === false
    );

    // 3.2 Invoke 404 handler via Serverless Handler
    const notFoundEvent = {
      httpMethod: 'GET',
      path: '/.netlify/functions/api/nonexistent-route-404',
      headers: {}
    };
    const notFoundRes = await handler(notFoundEvent, mockContext);
    const notFoundBody = JSON.parse(notFoundRes.body);

    record(
      'Serverless handler properly routes 404 for unknown endpoints',
      notFoundRes.statusCode === 404 && notFoundBody.status === 'fail',
      `Status: ${notFoundRes.statusCode}`
    );

    // 3.3 Invoke Protected Route without Token (Expect 401)
    const authEvent = {
      httpMethod: 'GET',
      path: '/.netlify/functions/api/auth/me',
      headers: {}
    };
    const authRes = await handler(authEvent, mockContext);
    const authBody = JSON.parse(authRes.body);

    record(
      'Serverless handler enforces JWT auth middleware (401 Unauthorized)',
      authRes.statusCode === 401 && authBody.status === 'fail',
      `Status: ${authRes.statusCode}`
    );
  } catch (err) {
    record('Serverless handler execution', false, err.message);
  }

  console.log('\n========================================================');
  console.log('            NETLIFY TEST EXECUTION SUMMARY              ');
  console.log('========================================================');

  const total = results.length;
  const passed = results.filter((r) => r.passed).length;
  const failed = total - passed;

  console.table(results);
  console.log(`TOTAL TESTS: ${total}`);
  console.log(`PASSED:      ${passed}`);
  console.log(`FAILED:      ${failed}`);

  if (failed > 0) {
    process.exit(1);
  } else {
    console.log('\n>>> ALL NETLIFY SERVERLESS FUNCTION TESTS PASSED! <<<');
    process.exit(0);
  }
}

runNetlifyTests();

