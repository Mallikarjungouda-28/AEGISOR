const mongoose = require('mongoose');

let cachedConnection = null;
let cachedPromise = null;

/**
 * Connect to MongoDB Atlas database with connection caching for serverless environments
 * Reuses existing active connection across warm Netlify Function invocations
 */
const connectDB = async () => {
  // 1. If connection is already open and ready, reuse immediately
  if (mongoose.connection.readyState === 1) {
    return mongoose.connection;
  }

  // 2. If connection is actively in progress, await the ongoing promise
  if (mongoose.connection.readyState === 2 && cachedPromise) {
    return cachedPromise;
  }

  const mongoURI = process.env.MONGODB_URI;

  if (!mongoURI) {
    throw new Error('MONGODB_URI is not defined in the environment variables.');
  }

  // 3. Initiate new connection and cache the promise
  if (!cachedPromise) {
    cachedPromise = mongoose
      .connect(mongoURI, {
        serverSelectionTimeoutMS: 8000,
        maxPoolSize: 10
      })
      .then((conn) => {
        console.log('[AEGISOR] MongoDB Connected successfully');
        cachedConnection = conn;
        return conn;
      })
      .catch((err) => {
        cachedPromise = null;
        cachedConnection = null;
        console.error(`[AEGISOR] MongoDB Connection Error: ${err.message}`);
        throw err;
      });
  }

  return cachedPromise;
};

module.exports = connectDB;
