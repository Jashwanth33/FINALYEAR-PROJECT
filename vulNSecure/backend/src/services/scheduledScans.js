const cron = require('node-cron');
const { Scan, User, ScheduledScan } = require('../models');
const { performScan } = require('./scannerService');
const { logger } = require('../utils/logger');

// Store active cron jobs
const activeJobs = new Map();

// Initialize scheduled scans from database
const initializeScheduledScans = async () => {
  try {
    const scheduledScans = await ScheduledScan.findAll({
      where: { enabled: true }
    });
    
    for (const scheduled of scheduledScans) {
      scheduleJob(scheduled);
    }
    
    logger.info('Initialized ' + scheduledScans.length + ' scheduled scans');
  } catch (error) {
    logger.error('Failed to initialize scheduled scans: ' + error.message);
  }
};

// Schedule a job
const scheduleJob = (scheduledScan) => {
  const { id, target, frequency, dayOfWeek, time, userId, type } = scheduledScan;
  
  // Build cron expression
  const cronExpression = buildCronExpression(frequency, dayOfWeek, time);
  
  if (!cronExpression) {
    logger.error('Invalid cron expression for scheduled scan: ' + id);
    return;
  }
  
  // Cancel existing job if any
  if (activeJobs.has(id)) {
    activeJobs.get(id).stop();
  }
  
  // Create new job
  const job = cron.schedule(cronExpression, async () => {
    logger.info('Running scheduled scan: ' + target);
    
    try {
      // Create scan
      const scan = await Scan.create({
        userId,
        name: 'Scheduled Scan: ' + target,
        target,
        type: type || 'web',
        status: 'pending'
      });
      
      // Update status to running
      await scan.update({ status: 'running', startTime: new Date() });
      
      // Run scan
      await performScan(target, scan.id);
      
      // Get vulnerabilities
      const { Vulnerability } = require('../models');
      const vulnerabilities = await Vulnerability.findAll({ where: { scanId: scan.id } });
      
      // Update scan
      await scan.update({
        status: 'completed',
        progress: 100,
        endTime: new Date(),
        summary: {
          critical: vulnerabilities.filter(v => v.severity === 'critical').length,
          high: vulnerabilities.filter(v => v.severity === 'high').length,
          medium: vulnerabilities.filter(v => v.severity === 'medium').length,
          low: vulnerabilities.filter(v => v.severity === 'low').length,
          total: vulnerabilities.length
        }
      });
      
      // Update last run time
      await ScheduledScan.update(
        { lastRunAt: new Date() },
        { where: { id } }
      );
      
      logger.info('Scheduled scan completed: ' + target);
      
    } catch (error) {
      logger.error('Scheduled scan failed: ' + error.message);
    }
  });
  
  activeJobs.set(id, job);
  logger.info('Scheduled job for: ' + target + ' (' + cronExpression + ')');
};

// Build cron expression from frequency settings
const buildCronExpression = (frequency, dayOfWeek, time) => {
  const [hour, minute] = (time || '02:00').split(':');
  
  switch (frequency) {
    case 'daily':
      return `${minute} ${hour} * * *`;
    case 'weekly':
      const days = { sunday: 0, monday: 1, tuesday: 2, wednesday: 3, thursday: 4, friday: 5, saturday: 6 };
      return `${minute} ${hour} * * ${days[dayOfWeek] || 1}`;
    case 'monthly':
      return `${minute} ${hour} 1 * *`;
    default:
      return null;
  }
};

// Create new scheduled scan
const createScheduledScan = async (data) => {
  try {
    const scheduled = await ScheduledScan.create({
      userId: data.userId,
      name: data.name,
      target: data.target,
      type: data.type || 'web',
      frequency: data.frequency,
      dayOfWeek: data.dayOfWeek,
      time: data.time,
      enabled: true
    });
    
    scheduleJob(scheduled);
    return scheduled;
  } catch (error) {
    logger.error('Failed to create scheduled scan: ' + error.message);
    throw error;
  }
};

// Update scheduled scan
const updateScheduledScan = async (id, data) => {
  try {
    await ScheduledScan.update(data, { where: { id } });
    
    const scheduled = await ScheduledScan.findByPk(id);
    if (scheduled && scheduled.enabled) {
      scheduleJob(scheduled);
    } else if (activeJobs.has(id)) {
      activeJobs.get(id).stop();
      activeJobs.delete(id);
    }
    
    return scheduled;
  } catch (error) {
    logger.error('Failed to update scheduled scan: ' + error.message);
    throw error;
  }
};

// Delete scheduled scan
const deleteScheduledScan = async (id) => {
  try {
    if (activeJobs.has(id)) {
      activeJobs.get(id).stop();
      activeJobs.delete(id);
    }
    
    await ScheduledScan.destroy({ where: { id } });
  } catch (error) {
    logger.error('Failed to delete scheduled scan: ' + error.message);
    throw error;
  }
};

module.exports = {
  initializeScheduledScans,
  createScheduledScan,
  updateScheduledScan,
  deleteScheduledScan
};
