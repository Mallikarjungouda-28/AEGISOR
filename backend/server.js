const app = require('./app');
const connectDB = require('./config/db');
const mongoose = require('mongoose');

const PORT = process.env.PORT || 5000;
let server;

const startServer = async () => {
  try {
    // Connect to MongoDB Atlas first
    await connectDB();

    server = app.listen(PORT, () => {
      console.log(`[AEGISOR] Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error(`[AEGISOR] Failed to start server: ${error.message}`);
    process.exit(1);
  }
};

// Graceful shutdown handling
const handleGracefulShutdown = async (signal) => {
  console.log(`\n[AEGISOR] Received ${signal}. Gracefully shutting down...`);
  if (server) {
    server.close(() => {
      console.log('[AEGISOR] HTTP server closed.');
    });
  }
  try {
    await mongoose.connection.close(false);
    console.log('[AEGISOR] MongoDB connection closed.');
  } catch (err) {
    console.error(`[AEGISOR] Error during MongoDB disconnection: ${err.message}`);
  }
  process.exit(0);
};

process.on('SIGINT', () => handleGracefulShutdown('SIGINT'));
process.on('SIGTERM', () => handleGracefulShutdown('SIGTERM'));

// Start server if not running in test mode
if (process.env.NODE_ENV !== 'test') {
  startServer();
}

module.exports = app;
