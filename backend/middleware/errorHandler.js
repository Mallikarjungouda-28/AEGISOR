/**
 * Centralized global error handling middleware for Express
 */
const errorHandler = (err, req, res, next) => {
  console.error(`[AEGISOR Unhandled Error] ${req.method} ${req.originalUrl}:`, err);

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    const messages = Object.values(err.errors).map((e) => e.message);
    return res.status(400).json({
      status: 'fail',
      message: messages.join(', ')
    });
  }

  // Mongoose duplicate key error
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue || {})[0] || 'field';
    return res.status(409).json({
      status: 'fail',
      message: `Duplicate value for ${field}. Please use another value.`
    });
  }

  // Mongoose bad ObjectId CastError
  if (err.name === 'CastError') {
    return res.status(400).json({
      status: 'fail',
      message: `Invalid ID format for ${err.path}: ${err.value}`
    });
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      status: 'fail',
      message: 'Invalid authorization token'
    });
  }

  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({
      status: 'fail',
      message: 'Authorization token has expired'
    });
  }

  const statusCode = res.statusCode && res.statusCode !== 200 ? res.statusCode : 500;

  return res.status(statusCode).json({
    status: 'error',
    message: err.message || 'Internal server error occurred'
  });
};

module.exports = { errorHandler };

