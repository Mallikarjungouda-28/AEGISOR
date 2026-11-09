const express = require('express');
const dotenv = require('dotenv');
const connectDB = require('./config/db');
const authRoutes = require('./routes/authRoutes');

// Load environment variables from .env file
dotenv.config();

const app = express();

// Body parser middleware
app.use(express.json());

// API Routes
app.use('/api/auth', authRoutes);

// Health check endpoint
app.get('/', (req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'AEGISOR Backend API is running'
  });
});

const PORT = process.env.PORT || 5000;

const startServer = async () => {
  try {
    // Connect to MongoDB Atlas and await completion
    await connectDB();

    // Start Express server after successful database connection
    app.listen(PORT, () => {
      console.log(`[AEGISOR] Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error(`[AEGISOR] Failed to start server: ${error.message}`);
    process.exit(1);
  }
};

startServer();
