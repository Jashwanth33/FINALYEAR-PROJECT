const express = require('express');
const { Op } = require('sequelize');
const { Scan, Vulnerability, Leak, CVE, Notification, User } = require('../models');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');
const { logger } = require('../utils/logger');

const router = express.Router();

// @route   GET /api/dashboard/stats
// @desc    Get dashboard statistics
// @access  Private
router.get('/stats', authenticateToken, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;

  // Base query conditions
  const whereCondition = userRole === 'admin' ? {} : { userId };

  // Get scan statistics
  const totalScans = await Scan.count({ where: whereCondition });
  const completedScans = await Scan.count({ 
    where: { ...whereCondition, status: 'completed' } 
  });
  const runningScans = await Scan.count({ 
    where: { ...whereCondition, status: 'running' } 
  });
  const failedScans = await Scan.count({ 
    where: { ...whereCondition, status: 'failed' } 
  });

  // Get vulnerability statistics
  const vulnerabilityStats = await Vulnerability.findAll({
    attributes: [
      'severity',
      [require('sequelize').fn('COUNT', require('sequelize').col('Vulnerability.id')), 'count']
    ],
    include: [{
      model: Scan,
      as: 'scan',
      where: whereCondition,
      attributes: []
    }],
    group: ['severity']
  });

  // Get leak statistics
  const leakStats = await Leak.findAll({
    attributes: [
      'severity',
      [require('sequelize').fn('COUNT', require('sequelize').col('Leak.id')), 'count']
    ],
    include: [{
      model: Scan,
      as: 'scan',
      where: whereCondition,
      attributes: []
    }],
    group: ['severity']
  });

  // Get recent activity
  const recentScans = await Scan.findAll({
    where: whereCondition,
    order: [['createdAt', 'DESC']],
    limit: 5,
    include: [{
      model: User,
      as: 'user',
      attributes: ['username', 'firstName', 'lastName']
    }]
  });

  // Get critical vulnerabilities
  const criticalVulnerabilities = await Vulnerability.findAll({
    where: { severity: 'critical' },
    include: [{
      model: Scan,
      as: 'scan',
      where: whereCondition,
      attributes: []
    }],
    order: [['createdAt', 'DESC']],
    limit: 10
  });

  // Get unread notifications count
  const unreadNotifications = await Notification.count({
    where: { userId, isRead: false }
  });

  // Format vulnerability stats
  const vulnerabilityCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };

  vulnerabilityStats.forEach(stat => {
    vulnerabilityCounts[stat.severity] = parseInt(stat.dataValues.count);
  });

  // Format leak stats
  const leakCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  };

  leakStats.forEach(stat => {
    leakCounts[stat.severity] = parseInt(stat.dataValues.count);
  });

  res.json({
    success: true,
    data: {
      scans: {
        total: totalScans,
        completed: completedScans,
        running: runningScans,
        failed: failedScans
      },
      vulnerabilities: vulnerabilityCounts,
      leaks: leakCounts,
      recentScans,
      criticalVulnerabilities,
      unreadNotifications
    }
  });
}));

// @route   GET /api/dashboard/charts/vulnerabilities
// @desc    Get vulnerability chart data
// @access  Private
router.get('/charts/vulnerabilities', authenticateToken, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;
  const { period = '30d' } = req.query;

  // Calculate date range
  const now = new Date();
  let startDate;
  
  switch (period) {
    case '7d':
      startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      break;
    case '30d':
      startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
      break;
    case '90d':
      startDate = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
      break;
    default:
      startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  }

  const whereCondition = userRole === 'admin' ? {} : { userId };

  // Get vulnerabilities by date
  const vulnerabilitiesByDate = await Vulnerability.findAll({
    attributes: [
      [require('sequelize').fn('DATE', require('sequelize').col('Vulnerability.createdAt')), 'date'],
      'severity',
      [require('sequelize').fn('COUNT', require('sequelize').col('Vulnerability.id')), 'count']
    ],
    include: [{
      model: Scan,
      as: 'scan',
      where: {
        ...whereCondition,
        createdAt: {
          [Op.gte]: startDate
        }
      },
      attributes: []
    }],
    group: [
      require('sequelize').fn('DATE', require('sequelize').col('Vulnerability.createdAt')),
      'severity'
    ],
    order: [[require('sequelize').fn('DATE', require('sequelize').col('Vulnerability.createdAt')), 'ASC']]
  });

  // Get vulnerabilities by severity
  const vulnerabilitiesBySeverity = await Vulnerability.findAll({
    attributes: [
      'severity',
      [require('sequelize').fn('COUNT', require('sequelize').col('id')), 'count']
    ],
    include: [{
      model: Scan,
      as: 'scan',
      where: {
        ...whereCondition,
        createdAt: {
          [Op.gte]: startDate
        }
      },
      attributes: []
    }],
    group: ['severity']
  });

  res.json({
    success: true,
    data: {
      byDate: vulnerabilitiesByDate,
      bySeverity: vulnerabilitiesBySeverity
    }
  });
}));

// @route   GET /api/dashboard/charts/leaks
// @desc    Get leak chart data
// @access  Private
router.get('/charts/leaks', authenticateToken, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;
  const { period = '30d' } = req.query;

  // Calculate date range
  const now = new Date();
  let startDate;
  
  switch (period) {
    case '7d':
      startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      break;
    case '30d':
      startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
      break;
    case '90d':
      startDate = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
      break;
    default:
      startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  }

  const whereCondition = userRole === 'admin' ? {} : { userId };

  // Get leaks by date
  const leaksByDate = await Leak.findAll({
    attributes: [
      [require('sequelize').fn('DATE', require('sequelize').col('Leak.createdAt')), 'date'],
      'severity',
      [require('sequelize').fn('COUNT', require('sequelize').col('Leak.id')), 'count']
    ],
    include: [{
      model: Scan,
      as: 'scan',
      where: {
        ...whereCondition,
        createdAt: {
          [Op.gte]: startDate
        }
      },
      attributes: []
    }],
    group: [
      require('sequelize').fn('DATE', require('sequelize').col('Leak.createdAt')),
      'severity'
    ],
    order: [[require('sequelize').fn('DATE', require('sequelize').col('Leak.createdAt')), 'ASC']]
  });

  // Get leaks by classification
  const leaksByClassification = await Leak.findAll({
    attributes: [
      'classification',
      [require('sequelize').fn('COUNT', require('sequelize').col('id')), 'count']
    ],
    include: [{
      model: Scan,
      as: 'scan',
      where: {
        ...whereCondition,
        createdAt: {
          [Op.gte]: startDate
        }
      },
      attributes: []
    }],
    group: ['classification']
  });

  res.json({
    success: true,
    data: {
      byDate: leaksByDate,
      byClassification: leaksByClassification
    }
  });
}));

// @route   GET /api/dashboard/activity
// @desc    Get recent activity feed
// @access  Private
router.get('/activity', authenticateToken, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;
  const { limit = 20, offset = 0 } = req.query;

  const whereCondition = userRole === 'admin' ? {} : { userId };

  // Get recent scans
  const recentScans = await Scan.findAll({
    where: whereCondition,
    order: [['createdAt', 'DESC']],
    limit: parseInt(limit),
    offset: parseInt(offset),
    include: [{
      model: User,
      as: 'user',
      attributes: ['username', 'firstName', 'lastName']
    }]
  });

  // Get recent vulnerabilities
  const recentVulnerabilities = await Vulnerability.findAll({
    include: [{
      model: Scan,
      as: 'scan',
      where: whereCondition,
      attributes: []
    }],
    order: [['createdAt', 'DESC']],
    limit: parseInt(limit),
    offset: parseInt(offset)
  });

  // Get recent leaks
  const recentLeaks = await Leak.findAll({
    include: [{
      model: Scan,
      as: 'scan',
      where: whereCondition,
      attributes: []
    }],
    order: [['createdAt', 'DESC']],
    limit: parseInt(limit),
    offset: parseInt(offset)
  });

  // Combine and sort activities
  const activities = [
    ...recentScans.map(scan => ({
      type: 'scan',
      id: scan.id,
      title: `Scan "${scan.name}" ${scan.status}`,
      description: `Target: ${scan.target}`,
      timestamp: scan.createdAt,
      severity: scan.status === 'failed' ? 'high' : 'info',
      user: scan.user
    })),
    ...recentVulnerabilities.map(vuln => ({
      type: 'vulnerability',
      id: vuln.id,
      title: `New ${vuln.severity} vulnerability found`,
      description: vuln.title,
      timestamp: vuln.createdAt,
      severity: vuln.severity
    })),
    ...recentLeaks.map(leak => ({
      type: 'leak',
      id: leak.id,
      title: `New ${leak.severity} leak detected`,
      description: leak.title,
      timestamp: leak.createdAt,
      severity: leak.severity
    }))
  ].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

  res.json({
    success: true,
    data: {
      activities: activities.slice(0, parseInt(limit))
    }
  });
}));

module.exports = router;
