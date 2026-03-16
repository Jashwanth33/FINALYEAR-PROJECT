const express = require('express');
const { param, query } = require('express-validator');
const { Op } = require('sequelize');
const { Leak, Scan, User } = require('../models');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { validateRequest, asyncHandler } = require('../middleware/errorHandler');

const router = express.Router();

// @route   GET /api/leaks
// @desc    Get all leaks
// @access  Private
router.get('/', authenticateToken, [
  query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
  query('severity').optional().isIn(['critical', 'high', 'medium', 'low', 'all']).withMessage('Invalid severity'),
  query('classification').optional().isIn(['pii', 'credentials', 'financial', 'personal', 'corporate', 'other', 'all']).withMessage('Invalid classification'),
  query('status').optional().isIn(['active', 'mitigated', 'resolved', 'all']).withMessage('Invalid status'),
  query('source').optional().isString().withMessage('Source must be a string'),
  query('search').optional().isString().withMessage('Search must be a string'),
  query('sortBy').optional().isString().withMessage('SortBy must be a string'),
  query('sortOrder').optional().isIn(['asc', 'desc']).withMessage('SortOrder must be asc or desc')
], validateRequest, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;
  const { page = 1, limit = 10, severity, classification, status, source, search, sortBy = 'createdAt', sortOrder = 'DESC' } = req.query;

  const whereCondition = {};
  if (severity && severity !== 'all') whereCondition.severity = severity;
  if (classification && classification !== 'all') whereCondition.classification = classification;
  
  // Map status filter to isProcessed/isVerified since Leak model doesn't have status field
  if (status && status !== 'all') {
    if (status === 'active') {
      whereCondition[Op.or] = [
        { isProcessed: false },
        { isVerified: false }
      ];
    } else if (status === 'resolved') {
      whereCondition.isProcessed = true;
      whereCondition.isVerified = true;
    } else if (status === 'mitigated') {
      whereCondition.isProcessed = true;
      whereCondition.isVerified = false;
    }
  }
  
  if (source && source !== 'all') whereCondition.source = source;
  
  // Handle search - combine with existing Op.or if status filter also uses Op.or
  if (search) {
    const searchConditions = [
      { title: { [Op.iLike]: `%${search}%` } },
      { content: { [Op.iLike]: `%${search}%` } },
      { source: { [Op.iLike]: `%${search}%` } }
    ];
    
    if (whereCondition[Op.or]) {
      // If Op.or already exists (from status filter), we need to combine them
      // For now, just add search to the existing conditions
      whereCondition[Op.and] = [
        { [Op.or]: whereCondition[Op.or] },
        { [Op.or]: searchConditions }
      ];
      delete whereCondition[Op.or];
    } else {
      whereCondition[Op.or] = searchConditions;
    }
  }

  const scanWhereCondition = userRole === 'admin' ? {} : { userId };

  const offset = (parseInt(page) - 1) * parseInt(limit);

  // Build order clause
  const orderColumn = sortBy === 'discoveredAt' ? 'createdAt' : (sortBy || 'createdAt');
  const orderDirection = sortOrder.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

  const { count, rows: leaks } = await Leak.findAndCountAll({
    where: whereCondition,
    include: [{
      model: Scan,
      as: 'scan',
      where: scanWhereCondition,
      attributes: ['id', 'name', 'type', 'target'],
      include: [{
        model: User,
        as: 'user',
        attributes: ['username', 'firstName', 'lastName']
      }]
    }],
    order: [[orderColumn, orderDirection]],
    limit: parseInt(limit),
    offset
  });

  // Calculate stats from all leaks (not just current page)
  const allLeaks = await Leak.findAll({
    where: whereCondition,
    include: [{
      model: Scan,
      as: 'scan',
      where: scanWhereCondition,
      attributes: []
    }]
  });

  const stats = {
    critical: allLeaks.filter(l => l.severity === 'critical').length,
    active: allLeaks.filter(l => !l.isProcessed || !l.isVerified).length, // Active = not processed or not verified
    resolved: allLeaks.filter(l => l.isProcessed && l.isVerified).length, // Resolved = processed and verified
    total_entities: allLeaks.reduce((sum, leak) => {
      const entities = leak.entities || {};
      if (typeof entities === 'object' && entities !== null) {
        return sum + (entities.total || Object.keys(entities).length || 0);
      }
      return sum;
    }, 0)
  };

  res.json({
    success: true,
    data: {
      leaks,
      stats,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: count,
        pages: Math.ceil(count / parseInt(limit))
      }
    }
  });
}));

// @route   GET /api/leaks/:id
// @desc    Get leak by ID
// @access  Private
router.get('/:id', authenticateToken, [
  param('id').isUUID().withMessage('Invalid leak ID')
], validateRequest, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;
  const { id } = req.params;

  const scanWhereCondition = userRole === 'admin' ? {} : { userId };

  const leak = await Leak.findOne({
    where: { id },
    include: [{
      model: Scan,
      as: 'scan',
      where: scanWhereCondition,
      attributes: ['id', 'name', 'type', 'target'],
      include: [{
        model: User,
        as: 'user',
        attributes: ['username', 'firstName', 'lastName']
      }]
    }]
  });

  if (!leak) {
    return res.status(404).json({
      success: false,
      message: 'Leak not found'
    });
  }

  res.json({
    success: true,
    data: { leak }
  });
}));

module.exports = router;
