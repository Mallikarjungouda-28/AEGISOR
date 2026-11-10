const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');

const authRoutes = require('./routes/authRoutes');
const projectRoutes = require('./routes/projectRoutes');
const scanRoutes = require('./routes/scanRoutes');
const vulnerabilityRoutes = require('./routes/vulnerabilityRoutes');
const dashboardRoutes = require('./routes/dashboardRoutes');
const { errorHandler } = require('./middleware/errorHandler');

// Load environment variables from .env file
dotenv.config();

const app = express();

// Trust reverse proxies (Netlify, AWS API Gateway, Heroku)
app.set('trust proxy', 1);

// 1. Security Headers via Helmet
app.use(helmet());

// 2. CORS configuration
const allowedOrigins = process.env.CLIENT_URL
  ? [process.env.CLIENT_URL]
  : ['http://localhost:3000', 'http://localhost:5173'];

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (mobile apps, curl, postman) or matching origin
      if (!origin || allowedOrigins.includes(origin) || process.env.NODE_ENV !== 'production') {
        callback(null, true);
      } else {
        callback(new Error('Blocked by CORS policy'));
      }
    },
    credentials: true
  })
);

// Client IP resolver safe for serverless and proxies
const getClientIp = (req) => {
  return (
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.headers['client-ip'] ||
    req.ip ||
    '127.0.0.1'
  );
};

// 3. Rate Limiting (General API protection)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 300, // Max 300 requests per IP per window
  standardHeaders: true,
  legacyHeaders: false,
  validate: { keyGeneratorIpFallback: false, ip: false },
  keyGenerator: getClientIp,
  message: {
    status: 'fail',
    message: 'Too many requests from this IP. Please try again after 15 minutes.'
  }
});
app.use('/api', apiLimiter);

// 4. Stricter Rate Limiter for Auth Endpoints (Brute-force protection)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { keyGeneratorIpFallback: false, ip: false },
  keyGenerator: getClientIp,
  message: {
    status: 'fail',
    message: 'Too many authentication attempts. Please try again later.'
  }
});
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

// 5. Body Parsing Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 6. Request Logger (Sanitizes credentials)
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    if (process.env.NODE_ENV !== 'test') {
      console.log(`[HTTP] ${req.method} ${req.originalUrl} ${res.statusCode} - ${duration}ms`);
    }
  });
  next();
});

// 7. Base Health Check Endpoint
app.get('/', (req, res) => {
  res.status(200).json({
    status: 'success',
    name: 'AEGISOR Security Platform API',
    tagline: 'Rule Out Every Vulnerability.',
    version: '1.0.0',
    database: mongoose.connection.readyState === 1 ? 'Connected' : 'Connecting'
  });
});

// 8. REST API Routes
app.use('/api/auth', authRoutes);
app.use('/api/projects', projectRoutes);
app.use('/api/scans', scanRoutes);
app.use('/api/vulnerabilities', vulnerabilityRoutes);
app.use('/api/dashboard', dashboardRoutes);

// 9. 404 Route Not Found Handler
app.use((req, res) => {
  res.status(404).json({
    status: 'fail',
    message: `API endpoint ${req.method} ${req.originalUrl} does not exist.`
  });
});

// 10. Centralized Error Handler
app.use(errorHandler);

module.exports = app;
