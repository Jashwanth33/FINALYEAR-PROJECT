const express = require('express');
const { body, param, query } = require('express-validator');
const { Op } = require('sequelize');
const { Scan, Vulnerability, User } = require('../models');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { validateRequest, asyncHandler } = require('../middleware/errorHandler');
const { logger } = require('../utils/logger');
const { runNmapScan, runZapScan } = require('../services/scannerService');

const router = express.Router();

// @route   GET /api/scans
// @desc    Get all scans
// @access  Private
router.get('/', authenticateToken, [
  query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
  query('status').optional().isIn(['pending', 'running', 'completed', 'failed', 'cancelled', 'all']).withMessage('Invalid status'),
  query('type').optional().isIn(['network', 'web', 'darkweb', 'all']).withMessage('Invalid type'),
  query('search').optional().isString().withMessage('Search must be a string'),
  query('sortBy').optional().isString().withMessage('SortBy must be a string'),
  query('sortOrder').optional().isIn(['asc', 'desc']).withMessage('SortOrder must be asc or desc')
], validateRequest, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;
  const { page = 1, limit = 10, status, type, search, sortBy = 'createdAt', sortOrder = 'DESC' } = req.query;

  const whereCondition = userRole === 'admin' ? {} : { userId };
  
  if (status && status !== 'all') whereCondition.status = status;
  if (type && type !== 'all') whereCondition.type = type;
  
  if (search) {
    whereCondition[Op.or] = [
      { name: { [Op.iLike]: `%${search}%` } },
      { target: { [Op.iLike]: `%${search}%` } },
      { description: { [Op.iLike]: `%${search}%` } }
    ];
  }

  const offset = (parseInt(page) - 1) * parseInt(limit);

  // Build order clause
  const orderColumn = sortBy === 'desc' ? 'createdAt' : sortBy || 'createdAt';
  const orderDirection = sortOrder.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

  const { count, rows: scans } = await Scan.findAndCountAll({
    where: whereCondition,
    include: [{
      model: User,
      as: 'user',
      attributes: ['username', 'firstName', 'lastName']
    }],
    order: [[orderColumn, orderDirection]],
    limit: parseInt(limit),
    offset
  });

  res.json({
    success: true,
    data: {
      scans,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: count,
        pages: Math.ceil(count / parseInt(limit))
      }
    }
  });
}));

// @route   GET /api/scans/:id
// @desc    Get scan by ID
// @access  Private
router.get('/:id', authenticateToken, [
  param('id').isUUID().withMessage('Invalid scan ID')
], validateRequest, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;
  const { id } = req.params;

  const whereCondition = userRole === 'admin' ? { id } : { id, userId };

  const scan = await Scan.findOne({
    where: whereCondition,
    include: [
      {
        model: User,
        as: 'user',
        attributes: ['username', 'firstName', 'lastName']
      },
      {
        model: Vulnerability,
        as: 'vulnerabilities',
        include: [{
          model: require('../models').CVE,
          as: 'cve',
          attributes: ['cveId', 'description', 'severity', 'cvssScore']
        }]
      }
    ]
  });

  if (!scan) {
    return res.status(404).json({
      success: false,
      message: 'Scan not found'
    });
  }

  res.json({
    success: true,
    data: { scan }
  });
}));

// @route   POST /api/scans
// @desc    Create new scan
// @access  Private
router.post('/', authenticateToken, requireRole(['admin', 'analyst', 'viewer']), [
  body('name').isLength({ min: 1, max: 100 }).withMessage('Scan name is required'),
  body('type').isIn(['network', 'web', 'darkweb']).withMessage('Invalid scan type'),
  body('target').isLength({ min: 1, max: 255 }).withMessage('Target is required'),
  body('configuration').optional().isObject().withMessage('Configuration must be an object')
], validateRequest, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const { name, type, target, configuration = {} } = req.body;

  const scan = await Scan.create({
    userId,
    name,
    type,
    target,
    configuration,
    status: 'pending'
  });

  logger.info('New scan created', {
    scanId: scan.id,
    userId,
    type,
    target
  });

  // Start scan based on type
  try {
    if (type === 'network') {
      await runNmapScan(scan.id, target, configuration);
    } else if (type === 'web') {
      await runZapScan(scan.id, target, configuration);
    } else if (type === 'darkweb') {
      // Dark web scan will be implemented separately
      await scan.update({ status: 'running' });
    }
  } catch (error) {
    logger.error('Failed to start scan', {
      scanId: scan.id,
      error: error.message
    });
    await scan.update({ 
      status: 'failed', 
      errorMessage: error.message 
    });
  }

  res.status(201).json({
    success: true,
    message: 'Scan created successfully',
    data: { scan }
  });
}));

// @route   PUT /api/scans/:id
// @desc    Update scan
// @access  Private
router.put('/:id', authenticateToken, [
  param('id').isUUID().withMessage('Invalid scan ID'),
  body('name').optional().isLength({ min: 1, max: 100 }).withMessage('Invalid scan name'),
  body('configuration').optional().isObject().withMessage('Configuration must be an object')
], validateRequest, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;
  const { id } = req.params;
  const { name, configuration } = req.body;

  const whereCondition = userRole === 'admin' ? { id } : { id, userId };

  const scan = await Scan.findOne({ where: whereCondition });

  if (!scan) {
    return res.status(404).json({
      success: false,
      message: 'Scan not found'
    });
  }

  if (scan.status === 'running') {
    return res.status(400).json({
      success: false,
      message: 'Cannot update running scan'
    });
  }

  const updateData = {};
  if (name) updateData.name = name;
  if (configuration) updateData.configuration = configuration;

  await scan.update(updateData);

  logger.info('Scan updated', {
    scanId: scan.id,
    userId,
    updatedFields: Object.keys(updateData)
  });

  res.json({
    success: true,
    message: 'Scan updated successfully',
    data: { scan }
  });
}));

// @route   DELETE /api/scans/:id
// @desc    Delete scan
// @access  Private
router.delete('/:id', authenticateToken, [
  param('id').isUUID().withMessage('Invalid scan ID')
], validateRequest, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;
  const { id } = req.params;

  const whereCondition = userRole === 'admin' ? { id } : { id, userId };

  const scan = await Scan.findOne({ where: whereCondition });

  if (!scan) {
    return res.status(404).json({
      success: false,
      message: 'Scan not found'
    });
  }

  if (scan.status === 'running') {
    return res.status(400).json({
      success: false,
      message: 'Cannot delete running scan'
    });
  }

  await scan.destroy();

  logger.info('Scan deleted', {
    scanId: scan.id,
    userId
  });

  res.json({
    success: true,
    message: 'Scan deleted successfully'
  });
}));

// @route   POST /api/scans/:id/cancel
// @desc    Cancel running scan
// @access  Private
router.post('/:id/cancel', authenticateToken, [
  param('id').isUUID().withMessage('Invalid scan ID')
], validateRequest, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;
  const { id } = req.params;

  const whereCondition = userRole === 'admin' ? { id } : { id, userId };

  const scan = await Scan.findOne({ where: whereCondition });

  if (!scan) {
    return res.status(404).json({
      success: false,
      message: 'Scan not found'
    });
  }

  if (scan.status !== 'running') {
    return res.status(400).json({
      success: false,
      message: 'Only running scans can be cancelled'
    });
  }

  await scan.update({ status: 'cancelled' });

  logger.info('Scan cancelled', {
    scanId: scan.id,
    userId
  });

  res.json({
    success: true,
    message: 'Scan cancelled successfully'
  });
}));

module.exports = router;
