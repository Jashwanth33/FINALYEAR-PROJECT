const express = require('express');
const { param, query } = require('express-validator');
const { Op } = require('sequelize');
const { CVE } = require('../models');
const { authenticateToken } = require('../middleware/auth');
const { validateRequest, asyncHandler } = require('../middleware/errorHandler');

const router = express.Router();

// @route   GET /api/cves
// @desc    Get all CVEs
// @access  Private
router.get('/', authenticateToken, [
  query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
  query('severity').optional().isIn(['critical', 'high', 'medium', 'low']).withMessage('Invalid severity'),
  query('search').optional().isLength({ min: 1, max: 100 }).withMessage('Search term must be between 1 and 100 characters')
], validateRequest, asyncHandler(async (req, res) => {
  const { page = 1, limit = 10, severity, search } = req.query;

  const whereCondition = { isActive: true };
  
  if (severity) whereCondition.severity = severity;
  
  if (search) {
    whereCondition[Op.or] = [
      { cveId: { [Op.iLike]: `%${search}%` } },
      { description: { [Op.iLike]: `%${search}%` } }
    ];
  }

  const offset = (parseInt(page) - 1) * parseInt(limit);

  const { count, rows: cves } = await CVE.findAndCountAll({
    where: whereCondition,
    order: [['publishedDate', 'DESC']],
    limit: parseInt(limit),
    offset
  });

  res.json({
    success: true,
    data: {
      cves,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: count,
        pages: Math.ceil(count / parseInt(limit))
      }
    }
  });
}));

// @route   GET /api/cves/:id
// @desc    Get CVE by ID
// @access  Private
router.get('/:id', authenticateToken, [
  param('id').isUUID().withMessage('Invalid CVE ID')
], validateRequest, asyncHandler(async (req, res) => {
  const { id } = req.params;

  const cve = await CVE.findOne({
    where: { id, isActive: true }
  });

  if (!cve) {
    return res.status(404).json({
      success: false,
      message: 'CVE not found'
    });
  }

  res.json({
    success: true,
    data: { cve }
  });
}));

// @route   GET /api/cves/cve/:cveId
// @desc    Get CVE by CVE ID
// @access  Private
router.get('/cve/:cveId', authenticateToken, [
  param('cveId').matches(/^CVE-\d{4}-\d{4,}$/).withMessage('Invalid CVE ID format')
], validateRequest, asyncHandler(async (req, res) => {
  const { cveId } = req.params;

  const cve = await CVE.findOne({
    where: { cveId, isActive: true }
  });

  if (!cve) {
    return res.status(404).json({
      success: false,
      message: 'CVE not found'
    });
  }

  res.json({
    success: true,
    data: { cve }
  });
}));

module.exports = router;
