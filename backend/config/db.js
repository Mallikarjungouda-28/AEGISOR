const mongoose = require('mongoose');

/**
 * Connect to MongoDB Atlas database
 */
const connectDB = async () => {
  try {
    const mongoURI = process.env.MONGODB_URI;

    if (!mongoURI) {
      throw new Error('MONGODB_URI is not defined in the environment variables.');
    }

    const conn = await mongoose.connect(mongoURI);

    console.log('[AEGISOR] MongoDB Connected successfully');
    return conn;
  } catch (error) {
    console.error(`[AEGISOR] MongoDB Connection Error: ${error.message}`);
    process.exit(1);
  }
};

module.exports = connectDB;
