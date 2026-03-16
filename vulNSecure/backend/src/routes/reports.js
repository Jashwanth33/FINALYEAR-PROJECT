const express = require('express');
const { body, param, query } = require('express-validator');
const { Op } = require('sequelize');
const { Report, Scan, User } = require('../models');
const { authenticateToken } = require('../middleware/auth');
const { validateRequest, asyncHandler } = require('../middleware/errorHandler');
const { generatePDFReport } = require('../services/reportService');

const router = express.Router();

// @route   GET /api/reports
// @desc    Get all reports
// @access  Private
router.get('/', authenticateToken, [
  query('search').optional().isString().withMessage('Search must be a string'),
  query('type').optional().isString().withMessage('Type must be a string'),
  query('format').optional().isString().withMessage('Format must be a string'),
  query('status').optional().isString().withMessage('Status must be a string'),
  query('dateRange').optional().isString().withMessage('DateRange must be a string'),
  query('sortBy').optional().isString().withMessage('SortBy must be a string'),
  query('sortOrder').optional().isIn(['asc', 'desc']).withMessage('SortOrder must be asc or desc')
], validateRequest, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;
  const { search, type, format, status, dateRange, sortBy = 'createdAt', sortOrder = 'DESC' } = req.query;

  const whereCondition = userRole === 'admin' ? {} : { userId };
  
  if (type && type !== 'all') whereCondition.type = type;
  if (format && format !== 'all') whereCondition.format = format;
  if (status && status !== 'all') whereCondition.status = status;
  
  if (search) {
    whereCondition[Op.or] = [
      { title: { [Op.iLike]: `%${search}%` } },
      { description: { [Op.iLike]: `%${search}%` } }
    ];
  }
  
  // Handle date range filter
  if (dateRange && dateRange !== 'all') {
    const now = new Date();
    let startDate;
    switch (dateRange) {
      case 'last_7_days':
        startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        break;
      case 'last_30_days':
        startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
        break;
      case 'last_90_days':
        startDate = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
        break;
      default:
        startDate = null;
    }
    if (startDate) {
      whereCondition.createdAt = { [Op.gte]: startDate };
    }
  }

  // Build order clause
  const orderColumn = sortBy || 'createdAt';
  const orderDirection = sortOrder.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

  const reports = await Report.findAll({
    where: whereCondition,
    include: [
      {
        model: User,
        as: 'user',
        attributes: ['username', 'firstName', 'lastName']
      },
      {
        model: Scan,
        as: 'scan',
        attributes: ['id', 'name', 'type', 'target']
      }
    ],
    order: [[orderColumn, orderDirection]]
  });

  // Calculate stats
  const stats = {
    total: reports.length,
    completed: reports.filter(r => r.status === 'completed').length,
    scheduled: reports.filter(r => r.status === 'scheduled').length,
    generating: reports.filter(r => r.status === 'generating').length
  };

  res.json({
    success: true,
    data: { 
      reports,
      stats
    }
  });
}));

// @route   GET /api/reports/:id
// @desc    Get report by ID
// @access  Private
router.get('/:id', authenticateToken, [
  param('id').isUUID().withMessage('Invalid report ID')
], validateRequest, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;
  const { id } = req.params;

  const whereCondition = userRole === 'admin' ? { id } : { id, userId };

  const report = await Report.findOne({
    where: whereCondition,
    include: [
      {
        model: User,
        as: 'user',
        attributes: ['username', 'firstName', 'lastName']
      },
      {
        model: Scan,
        as: 'scan',
        attributes: ['id', 'name', 'type', 'target']
      }
    ]
  });

  if (!report) {
    return res.status(404).json({
      success: false,
      message: 'Report not found'
    });
  }

  res.json({
    success: true,
    data: { report }
  });
}));

// @route   POST /api/reports
// @desc    Generate new report
// @access  Private
router.post('/', authenticateToken, [
  body('title').isLength({ min: 1, max: 255 }).withMessage('Report title is required'),
  body('type').isIn(['scan', 'leak', 'combined', 'custom']).withMessage('Invalid report type'),
  body('format').optional().isIn(['pdf', 'html', 'json', 'csv']).withMessage('Invalid report format'),
  body('scanId').optional().isUUID().withMessage('Invalid scan ID'),
  body('configuration').optional().isObject().withMessage('Configuration must be an object')
], validateRequest, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const { title, type, format = 'pdf', scanId, configuration = {} } = req.body;

  // Create report record
  const report = await Report.create({
    userId,
    scanId,
    title,
    type,
    format,
    status: 'pending',
    configuration
  });

  try {
    // Generate report
    const reportData = await generatePDFReport(report.id, type, scanId, configuration);
    
    await report.update({
      status: 'completed',
      filePath: reportData.filePath,
      fileName: reportData.fileName,
      fileSize: reportData.fileSize,
      summary: reportData.summary
    });

    res.status(201).json({
      success: true,
      message: 'Report generated successfully',
      data: { report }
    });
  } catch (error) {
    await report.update({
      status: 'failed',
      errorMessage: error.message
    });

    res.status(500).json({
      success: false,
      message: 'Failed to generate report',
      error: error.message
    });
  }
}));

// @route   GET /api/reports/:id/download
// @desc    Download report file
// @access  Private
router.get('/:id/download', authenticateToken, [
  param('id').isUUID().withMessage('Invalid report ID')
], validateRequest, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;
  const { id } = req.params;

  const whereCondition = userRole === 'admin' ? { id } : { id, userId };

  const report = await Report.findOne({
    where: whereCondition
  });

  if (!report) {
    return res.status(404).json({
      success: false,
      message: 'Report not found'
    });
  }

  if (report.status !== 'completed' || !report.filePath) {
    return res.status(400).json({
      success: false,
      message: 'Report not ready for download'
    });
  }

  res.download(report.filePath, report.fileName);
}));

module.exports = router;
