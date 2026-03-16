const express = require('express');
const { param, query, body } = require('express-validator');
const { Op } = require('sequelize');
const { Vulnerability, Scan, User } = require('../models');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { validateRequest, asyncHandler } = require('../middleware/errorHandler');

const router = express.Router();

// @route   GET /api/vulnerabilities
// @desc    Get all vulnerabilities
// @access  Private
router.get('/', authenticateToken, [
  query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
  query('severity').optional().isIn(['critical', 'high', 'medium', 'low', 'all']).withMessage('Invalid severity'),
  query('status').optional().isIn(['open', 'closed', 'mitigated', 'all']).withMessage('Invalid status'),
  query('category').optional().isString().withMessage('Category must be a string'),
  query('search').optional().isString().withMessage('Search must be a string'),
  query('sortBy').optional().isString().withMessage('SortBy must be a string'),
  query('sortOrder').optional().isIn(['asc', 'desc']).withMessage('SortOrder must be asc or desc')
], validateRequest, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;
  const { page = 1, limit = 10, severity, status, category, search, sortBy = 'discoveredAt', sortOrder = 'DESC' } = req.query;

  const whereCondition = {};
  if (severity && severity !== 'all') whereCondition.severity = severity;
  if (status && status !== 'all') whereCondition.status = status;
  if (category && category !== 'all') whereCondition.category = category;
  if (search) {
    whereCondition[Op.or] = [
      { title: { [Op.iLike]: `%${search}%` } },
      { description: { [Op.iLike]: `%${search}%` } }
    ];
  }

  const scanWhereCondition = userRole === 'admin' ? {} : { userId };

  const offset = (parseInt(page) - 1) * parseInt(limit);

  // Build order clause - map discoveredAt to createdAt since that's the actual column name
  const orderColumn = sortBy === 'discoveredAt' ? 'createdAt' : (sortBy || 'createdAt');
  const orderDirection = sortOrder.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

  const { count, rows: vulnerabilities } = await Vulnerability.findAndCountAll({
    where: whereCondition,
    include: [{
      model: Scan,
      as: 'scan',
      where: scanWhereCondition,
      attributes: ['id', 'name', 'target', 'status', 'createdAt'],
      include: [{
        model: User,
        as: 'user',
        attributes: ['id', 'username', 'firstName', 'lastName']
      }]
    }],
    limit: parseInt(limit),
    offset,
    order: [[orderColumn, orderDirection]]
  });

  // Map vulnerabilities to include target and discoveredAt for frontend compatibility
  const mappedVulnerabilities = vulnerabilities.map(vuln => {
    const vulnData = vuln.toJSON();
    return {
      ...vulnData,
      target: vulnData.scan?.target || 'Unknown',
      discoveredAt: vulnData.createdAt,
      remediation: vulnData.remediation || null
    };
  });

  const totalPages = Math.ceil(count / parseInt(limit));

  // Calculate stats from all vulnerabilities (not just current page)
  const allVulns = await Vulnerability.findAll({
    where: whereCondition,
    include: [{
      model: Scan,
      as: 'scan',
      where: scanWhereCondition,
      attributes: []
    }]
  });

  const stats = {
    critical: allVulns.filter(v => v.severity === 'critical').length,
    high: allVulns.filter(v => v.severity === 'high').length,
    medium: allVulns.filter(v => v.severity === 'medium').length,
    low: allVulns.filter(v => v.severity === 'low').length
  };

  res.json({
    success: true,
    data: {
      vulnerabilities: mappedVulnerabilities,
      stats,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: count,
        pages: totalPages
      }
    }
  });
}));

// @route   GET /api/vulnerabilities/:id
// @desc    Get vulnerability by ID
// @access  Private
router.get('/:id', authenticateToken, [
  param('id').isUUID().withMessage('Invalid vulnerability ID')
], validateRequest, asyncHandler(async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;
  const userRole = req.user.role;

  const scanWhereCondition = userRole === 'admin' ? {} : { userId };

  const vulnerability = await Vulnerability.findOne({
    where: { id },
    include: [{
      model: Scan,
      as: 'scan',
      where: scanWhereCondition,
      attributes: ['id', 'name', 'target', 'status', 'createdAt'],
      include: [{
        model: User,
        as: 'user',
        attributes: ['id', 'username', 'firstName', 'lastName']
      }]
    }]
  });

  if (!vulnerability) {
    return res.status(404).json({
      success: false,
      message: 'Vulnerability not found'
    });
  }

  res.json({
    success: true,
    data: { vulnerability }
  });
}));

// @route   PUT /api/vulnerabilities/:id/status
// @desc    Update vulnerability status
// @access  Private
router.put('/:id/status', authenticateToken, [
  param('id').isUUID().withMessage('Invalid vulnerability ID'),
  body('status').isIn(['open', 'in_progress', 'resolved', 'false_positive']).withMessage('Invalid status')
], validateRequest, asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  const userId = req.user.id;
  const userRole = req.user.role;

  const scanWhereCondition = userRole === 'admin' ? {} : { userId };

  const vulnerability = await Vulnerability.findOne({
    where: { id },
    include: [{
      model: Scan,
      as: 'scan',
      where: scanWhereCondition
    }]
  });

  if (!vulnerability) {
    return res.status(404).json({
      success: false,
      message: 'Vulnerability not found'
    });
  }

  await vulnerability.update({ status });

  res.json({
    success: true,
    message: 'Vulnerability status updated successfully',
    data: { vulnerability }
  });
}));

module.exports = router;