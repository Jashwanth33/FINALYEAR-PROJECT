const express = require('express');
const { body, param } = require('express-validator');
const { Schedule, Scan, User } = require('../models');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { validateRequest, asyncHandler } = require('../middleware/errorHandler');
const { logger } = require('../utils/logger');
const cron = require('node-cron');

const router = express.Router();

// In-memory job storage (in production, use a database)
const scheduledJobs = new Map();

// @route   GET /api/schedules
// @desc    Get all scheduled scans
// @access  Private (Admin, Analyst)
router.get('/', authenticateToken, requireRole(['admin', 'analyst']), asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;

  const where = userRole === 'admin' ? {} : { userId };

  const schedules = await Schedule.findAll({
    where,
    include: [{ model: User, attributes: ['id', 'username', 'firstName', 'lastName'] }],
    order: [['nextRun', 'ASC']]
  });

  res.json({ success: true, data: { schedules } });
}));

// @route   POST /api/schedules
// @desc    Create a scheduled scan
// @access  Private (Admin, Analyst)
router.post('/', authenticateToken, requireRole(['admin', 'analyst']), [
  body('name').notEmpty().withMessage('Name is required'),
  body('type').isIn(['network', 'web', 'darkweb']).withMessage('Invalid scan type'),
  body('target').notEmpty().withMessage('Target is required'),
  body('cronExpression').notEmpty().withMessage('Schedule is required'),
  body('isActive').optional().isBoolean()
], validateRequest, asyncHandler(async (req, res) => {
  const { name, type, target, cronExpression, configuration, isActive = true } = req.body;
  const userId = req.user.id;

  // Validate cron expression
  if (!cron.validate(cronExpression)) {
    return res.status(400).json({ success: false, message: 'Invalid cron expression' });
  }

  const schedule = await Schedule.create({
    userId,
    name,
    type,
    target,
    cronExpression,
    configuration: configuration || {},
    isActive,
    lastRun: null,
    nextRun: getNextRunTime(cronExpression),
    status: 'pending'
  });

  // Schedule the job
  if (isActive) {
    scheduleJob(schedule);
  }

  logger.info('Scheduled scan created', { scheduleId: schedule.id, name, cronExpression });

  res.status(201).json({
    success: true,
    message: 'Scheduled scan created successfully',
    data: { schedule }
  });
}));

// @route   PUT /api/schedules/:id
// @desc    Update scheduled scan
// @access  Private (Admin, Analyst)
router.put('/:id', authenticateToken, requireRole(['admin', 'analyst']), [
  param('id').isUUID().withMessage('Invalid schedule ID')
], validateRequest, asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { name, type, target, cronExpression, configuration, isActive } = req.body;
  const userId = req.user.id;
  const userRole = req.user.role;

  const whereCondition = userRole === 'admin' ? { id } : { id, userId };
  const schedule = await Schedule.findOne({ where: whereCondition });

  if (!schedule) {
    return res.status(404).json({ success: false, message: 'Schedule not found' });
  }

  // Update fields
  if (name) schedule.name = name;
  if (type) schedule.type = type;
  if (target) schedule.target = target;
  if (configuration) schedule.configuration = configuration;
  
  if (cronExpression) {
    if (!cron.validate(cronExpression)) {
      return res.status(400).json({ success: false, message: 'Invalid cron expression' });
    }
    schedule.cronExpression = cronExpression;
    schedule.nextRun = getNextRunTime(cronExpression);
  }

  if (isActive !== undefined) {
    schedule.isActive = isActive;
    
    // Handle job scheduling
    if (isActive) {
      scheduleJob(schedule);
    } else {
      cancelJob(schedule.id);
    }
  }

  await schedule.save();

  res.json({
    success: true,
    message: 'Schedule updated successfully',
    data: { schedule }
  });
}));

// @route   DELETE /api/schedules/:id
// @desc    Delete scheduled scan
// @access  Private (Admin)
router.delete('/:id', authenticateToken, requireRole(['admin']), [
  param('id').isUUID().withMessage('Invalid schedule ID')
], validateRequest, asyncHandler(async (req, res) => {
  const { id } = req.params;

  const schedule = await Schedule.findByPk(id);

  if (!schedule) {
    return res.status(404).json({ success: false, message: 'Schedule not found' });
  }

  // Cancel any running job
  cancelJob(schedule.id);

  await schedule.destroy();

  res.json({ success: true, message: 'Schedule deleted successfully' });
}));

// @route   POST /api/schedules/:id/run
// @desc    Manually trigger a scheduled scan
// @access  Private (Admin, Analyst)
router.post('/:id/run', authenticateToken, requireRole(['admin', 'analyst']), [
  param('id').isUUID().withMessage('Invalid schedule ID')
], validateRequest, asyncHandler(async (req, res) => {
  const { id } = req.params;

  const schedule = await Schedule.findByPk(id);

  if (!schedule) {
    return res.status(404).json({ success: false, message: 'Schedule not found' });
  }

  // Create a new scan immediately
  const scan = await Scan.create({
    userId: schedule.userId,
    name: `Manual: ${schedule.name}`,
    type: schedule.type,
    target: schedule.target,
    configuration: schedule.configuration,
    status: 'pending'
  });

  // Update schedule
  schedule.lastRun = new Date();
  schedule.nextRun = getNextRunTime(schedule.cronExpression);
  schedule.runCount = (schedule.runCount || 0) + 1;
  await schedule.save();

  logger.info('Manual scheduled scan triggered', { scheduleId: id, scanId: scan.id });

  res.json({
    success: true,
    message: 'Scan triggered successfully',
    data: { scan }
  });
}));

// Helper functions
const getNextRunTime = (cronExpression) => {
  try {
    const cronJob = cron.schedule(cronExpression, () => {}, { scheduled: false });
    const next = cronJob.nextDates(1);
    return next.toDate();
  } catch (e) {
    return null;
  }
};

const scheduleJob = (schedule) => {
  try {
    // Cancel existing job if any
    cancelJob(schedule.id);

    if (!schedule.isActive) return;

    const job = cron.schedule(schedule.cronExpression, async () => {
      logger.info('Running scheduled scan', { scheduleId: schedule.id });

      try {
        // Create scan
        const scan = await Scan.create({
          userId: schedule.userId,
          name: `Scheduled: ${schedule.name}`,
          type: schedule.type,
          target: schedule.target,
          configuration: schedule.configuration,
          status: 'pending'
        });

        // Update schedule
        schedule.lastRun = new Date();
        schedule.nextRun = getNextRunTime(schedule.cronExpression);
        schedule.runCount = (schedule.runCount || 0) + 1;
        schedule.status = 'running';
        await schedule.save();

        // Note: Actual scan execution would be handled by the scanner service
        logger.info('Scheduled scan created', { scanId: scan.id });

      } catch (error) {
        logger.error('Scheduled scan failed', { scheduleId: schedule.id, error: error.message });
        schedule.status = 'error';
        await schedule.save();
      }
    });

    scheduledJobs.set(schedule.id, job);
    logger.info('Job scheduled', { scheduleId: schedule.id, cron: schedule.cronExpression });

  } catch (error) {
    logger.error('Failed to schedule job', { scheduleId: schedule.id, error: error.message });
  }
};

const cancelJob = (scheduleId) => {
  const job = scheduledJobs.get(scheduleId);
  if (job) {
    job.stop();
    scheduledJobs.delete(scheduleId);
  }
};

// Initialize scheduled jobs on startup
const initializeScheduledJobs = async () => {
  try {
    const activeSchedules = await Schedule.findAll({ where: { isActive: true } });
    
    for (const schedule of activeSchedules) {
      scheduleJob(schedule);
    }

    logger.info('Initialized scheduled jobs', { count: activeSchedules.length });
  } catch (error) {
    logger.error('Failed to initialize scheduled jobs', { error: error.message });
  }
};

// Export for server startup
module.exports = { router, initializeScheduledJobs };
