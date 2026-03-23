const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
require('dotenv').config();

const { sequelize } = require('./config/database');
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const scanRoutes = require('./routes/scans');
const vulnerabilitiesRoutes = require('./routes/vulnerabilities');
const leakRoutes = require('./routes/leaks');
const cveRoutes = require('./routes/cves');
const reportRoutes = require('./routes/reports');
const dashboardRoutes = require('./routes/dashboard');
const analyticsRoutes = require('./routes/analytics');
const scheduleRoutes = require('./routes/schedules').router;
const assetRoutes = require('./routes/assets');
const advancedRoutes = require('./routes/advanced');
const extendedRoutes = require('./routes/extended');
const enterpriseRoutes = require('./routes/enterprise');
const nextGenRoutes = require('./routes/nextgen');
const { errorHandler } = require('./middleware/errorHandler');
const { initializeScheduledJobs } = require('./routes/schedules');
const { logger } = require('./utils/logger');

const app = express();
const PORT = process.env.PORT || 5000;

// CORS configuration - MUST be before other middleware
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://yourdomain.com'] 
    : ['http://localhost:3000', 'http://127.0.0.1:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  exposedHeaders: ['Content-Range', 'X-Content-Range']
}));

// Security middleware - configure Helmet to not interfere with CORS
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  crossOriginEmbedderPolicy: false
}));
app.use(compression());

// Rate limiting - increased limits for development
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 1 * 60 * 1000, // 1 minute
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 500, // limit each IP to 500 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true // Don't count successful requests
});

const speedLimiter = slowDown({
  windowMs: 1 * 60 * 1000,
  delayAfter: 200,
  delayMs: () => 100,
  validate: { delayMs: false }
});

app.use(limiter);
app.use(speedLimiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Logging
if (process.env.NODE_ENV !== 'test') {
  app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV 
  });
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/scans', scanRoutes);
app.use('/api/vulnerabilities', vulnerabilitiesRoutes);
app.use('/api/leaks', leakRoutes);
app.use('/api/cves', cveRoutes);
app.use('/api/reports', reportRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/analytics', analyticsRoutes);
app.use('/api/schedules', scheduleRoutes);
app.use('/api/assets', assetRoutes);
app.use('/api/advanced', advancedRoutes);
app.use('/api/extended', extendedRoutes);
app.use('/api/enterprise', enterpriseRoutes);
app.use('/api/nextgen', nextGenRoutes);
app.use('/api/notifications', require('./routes/notifications'));
app.use('/api/pro', require('./routes/proFeatures'));
app.use('/api/enhanced', require('./routes/enhanced'));
app.use('/api/professional', require('./routes/professional'));
app.use('/api/advanced', require('./routes/advancedPro'));
app.use('/api/complete', require('./routes/complete'));
app.use('/api/new', require('./routes/newFeatures'));
app.use('/api/final', require('./routes/completeNew'));

// Static files for uploads
app.use('/uploads', express.static('uploads'));

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ 
    success: false, 
    message: 'Route not found' 
  });
});

// Error handling middleware
app.use(errorHandler);

// Database connection and server startup
const startServer = async () => {
  try {
    await sequelize.authenticate();
    logger.info('Database connection established successfully');
    
    // Sync database models
    if (process.env.NODE_ENV === 'development') {
      await sequelize.sync({ alter: false, force: false });
      logger.info('Database models synchronized');
    }
    
    app.listen(PORT, () => {
      logger.info(`Server running on port ${PORT} in ${process.env.NODE_ENV} mode`);
      initializeScheduledJobs().catch(err => {
        logger.error('Failed to initialize scheduled jobs:', err);
      });
    });
  } catch (error) {
    logger.error('Unable to start server:', error);
    process.exit(1);
  }
};

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received, shutting down gracefully');
  await sequelize.close();
  process.exit(0);
});

process.on('SIGINT', async () => {
  logger.info('SIGINT received, shutting down gracefully');
  await sequelize.close();
  process.exit(0);
});

startServer();

module.exports = app;
