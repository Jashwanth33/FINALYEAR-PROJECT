const express = require('express');
const { param, query, body } = require('express-validator');
const { Op } = require('sequelize');
const axios = require('axios');
const { CVE } = require('../models');
const { authenticateToken, requireRole } = require('../middleware/auth');
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

// @route   POST /api/cves/fetch
// @desc    Fetch CVEs from NVD API and store in database
// @access  Admin only
router.post('/fetch', authenticateToken, requireRole(['admin']), asyncHandler(async (req, res) => {
  const { keyword = 'web', limit = 20 } = req.body;
  
  try {
    // Fetch from NVD API
    const response = await axios.get(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${keyword}&resultsPerPage=${limit}`,
      { timeout: 30000 }
    );
    
    const nvdCves = response.data.vulnerabilities || [];
    let imported = 0;
    
    for (const item of nvdCves) {
      const cve = item.cve;
      const cveId = cve.id;
      const description = cve.descriptions?.find(d => d.lang === 'en')?.value || 'No description';
      
      // Get CVSS score
      let cvssScore = null;
      let cvssVector = null;
      let severity = 'medium';
      
      if (cve.metrics?.cvssMetricV31?.[0]?.cvssData) {
        cvssScore = cve.metrics.cvssMetricV31[0].cvssData.baseScore;
        cvssVector = cve.metrics.cvssMetricV31[0].cvssData.vectorString;
        if (cvssScore >= 9.0) severity = 'critical';
        else if (cvssScore >= 7.0) severity = 'high';
        else if (cvssScore >= 4.0) severity = 'medium';
        else severity = 'low';
      }
      
      // Check if already exists
      const existing = await CVE.findOne({ where: { cveId } });
      if (!existing) {
        await CVE.create({
          cveId,
          description,
          severity,
          cvssScore,
          cvssVector,
          publishedDate: cve.published,
          isActive: true
        });
        imported++;
      }
    }
    
    res.json({
      success: true,
      message: `Successfully imported ${imported} CVEs for keyword: ${keyword}`,
      data: { imported, keyword }
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to fetch CVEs from NVD: ' + error.message
    });
  }
}));

// @route   GET /api/cves/search/:query
// @desc    Search CVEs by keyword
// @access  Private
router.get('/search/:query', authenticateToken, asyncHandler(async (req, res) => {
  const { query: searchQuery } = req.params;
  const { limit = 10 } = req.query;
  
  const cves = await CVE.findAll({
    where: {
      cveId: { [Op.iLike]: `%${searchQuery}%` },
      isActive: true
    },
    order: [['cvssScore', 'DESC']],
    limit: parseInt(limit)
  });
  
  res.json({
    success: true,
    data: { cves }
  });
}));

module.exports = router;
