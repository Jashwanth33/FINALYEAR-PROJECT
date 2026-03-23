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

  const mappedVulnerabilities = vulnerabilities.map(vuln => {
    const vulnData = vuln.toJSON();
    return {
      ...vulnData,
      target: vulnData.scan?.target || 'Unknown',
      url: vulnData.url || `${vulnData.scan?.target || ''}`, // Include specific URL/endpoint
      discoveredAt: vulnData.createdAt,
      remediation: vulnData.remediation || null
    };
  });

  const totalPages = Math.ceil(count / parseInt(limit));

  res.json({
    success: true,
    data: {
      vulnerabilities: mappedVulnerabilities,
      stats: {
        critical: mappedVulnerabilities.filter(v => v.severity === 'critical').length,
        high: mappedVulnerabilities.filter(v => v.severity === 'high').length,
        medium: mappedVulnerabilities.filter(v => v.severity === 'medium').length,
        low: mappedVulnerabilities.filter(v => v.severity === 'low').length
      },
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: count,
        pages: totalPages
      }
    }
  });
}));

// POC Routes - Using /poc/:id pattern to avoid route conflicts
router.get('/poc/:vulnId', authenticateToken, requireRole(['admin', 'analyst']), asyncHandler(async (req, res) => {
  const { vulnId } = req.params;

  const vulnerability = await Vulnerability.findByPk(vulnId, {
    include: [{
      model: Scan,
      as: 'scan',
      include: [{ model: User, as: 'user', attributes: ['id', 'username', 'firstName', 'lastName'] }]
    }]
  });

  if (!vulnerability) {
    return res.status(404).json({ success: false, message: 'Vulnerability not found' });
  }

  res.json({
    success: true,
    data: {
      id: vulnerability.id,
      title: vulnerability.title,
      severity: vulnerability.severity,
      poc: vulnerability.poc,
      pocType: vulnerability.pocType,
      affectedEndpoints: vulnerability.affectedEndpoints,
      evidence: vulnerability.evidence,
      createdAt: vulnerability.createdAt
    }
  });
}));

router.get('/poc/:vulnId/download', authenticateToken, requireRole(['admin', 'analyst']), asyncHandler(async (req, res) => {
  const { vulnId } = req.params;

  const vulnerability = await Vulnerability.findByPk(vulnId);

  if (!vulnerability) {
    return res.status(404).json({ success: false, message: 'Vulnerability not found' });
  }

  if (!vulnerability.poc) {
    return res.status(404).json({ success: false, message: 'No POC available' });
  }

  const filename = `POC_${vulnerability.severity}_${vulnerability.title.replace(/[^a-zA-Z0-9]/g, '_')}.txt`;

  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

  const fullPoc = `
================================================================================
PROOF OF CONCEPT - VULNERABILITY REPORT
================================================================================
Vulnerability: ${vulnerability.title}
Severity: ${vulnerability.severity.toUpperCase()}
Status: ${vulnerability.status}
Target URL: ${vulnerability.url || 'N/A'}
Description: ${vulnerability.description}
Evidence: ${vulnerability.evidence}
================================================================================
POC:
${vulnerability.poc}
================================================================================
Generated by vulNSecure Platform - ${new Date().toISOString()}
================================================================================
`;

  res.send(fullPoc);
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
    return res.status(404).json({ success: false, message: 'Vulnerability not found' });
  }

  res.json({ success: true, data: { vulnerability } });
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
    include: [{ model: Scan, as: 'scan', where: scanWhereCondition }]
  });

  if (!vulnerability) {
    return res.status(404).json({ success: false, message: 'Vulnerability not found' });
  }

  await vulnerability.update({ status });

  res.json({ success: true, message: 'Status updated', data: { vulnerability } });
}));

// @route   PUT /api/vulnerabilities/:id
// @desc    Update vulnerability
// @access  Private (Admin, Analyst)
router.put('/:id', authenticateToken, requireRole(['admin', 'analyst']), [
  param('id').isUUID().withMessage('Invalid vulnerability ID')
], validateRequest, asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { title, description, solution, severity, status, falsePositiveReason } = req.body;

  const vulnerability = await Vulnerability.findByPk(id);

  if (!vulnerability) {
    return res.status(404).json({ success: false, message: 'Vulnerability not found' });
  }

  const updateData = {};
  if (title) updateData.title = title;
  if (description) updateData.description = description;
  if (solution) updateData.solution = solution;
  if (severity) updateData.severity = severity;
  if (status) {
    updateData.status = status;
    if (status === 'false_positive' && falsePositiveReason) {
      updateData.falsePositiveReason = falsePositiveReason;
      updateData.falsePositive = true;
    }
  }

  await vulnerability.update(updateData);

  res.json({ success: true, message: 'Vulnerability updated', data: { vulnerability } });
}));

// @route   DELETE /api/vulnerabilities/all
// @desc    Delete all vulnerabilities (clear false positives)
// @access  Private (Admin only)
router.delete('/all', authenticateToken, requireRole(['admin']), asyncHandler(async (req, res) => {
  const { scanId } = req.query;
  
  const whereCondition = scanId ? { scanId } : {};
  
  const deletedCount = await Vulnerability.destroy({
    where: whereCondition
  });

  res.json({ 
    success: true, 
    message: `Deleted ${deletedCount} vulnerabilities`,
    data: { deletedCount }
  });
}));

module.exports = router;
