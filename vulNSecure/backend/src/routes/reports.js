const express = require('express');
const { body, param, query } = require('express-validator');
const { Op } = require('sequelize');
const { Report, Scan, User, Vulnerability } = require('../models');
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

// @route   POST /api/reports/generate
// @desc    Generate new report (alternative endpoint)
// @access  Private
router.post('/generate', authenticateToken, [
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

// @route   GET /api/reports/export/:scanId
// @desc    Export scan results in various formats
// @access  Private
router.get('/export/:scanId', authenticateToken, [
  param('scanId').isUUID().withMessage('Invalid scan ID'),
  query('format').optional().isIn(['json', 'csv', 'html']).withMessage('Format must be json, csv, or html')
], validateRequest, asyncHandler(async (req, res) => {
  const { scanId } = req.params;
  const { format = 'json' } = req.query;
  const userId = req.user.id;
  const userRole = req.user.role;

  const scan = await Scan.findByPk(scanId, {
    include: [
      { model: Vulnerability, as: 'vulnerabilities' },
      { model: User, as: 'user', attributes: ['username', 'firstName', 'lastName'] }
    ]
  });

  if (!scan) {
    return res.status(404).json({ success: false, message: 'Scan not found' });
  }

  if (userRole !== 'admin' && scan.userId !== userId) {
    return res.status(403).json({ success: false, message: 'Access denied' });
  }

  const vulnerabilities = scan.vulnerabilities || [];
  
  let content, contentType, filename;
  
  if (format === 'json') {
    content = JSON.stringify({
      scan: {
        id: scan.id,
        name: scan.name,
        target: scan.target,
        status: scan.status,
        createdAt: scan.createdAt,
        summary: scan.summary
      },
      vulnerabilities: vulnerabilities.map(v => ({
        title: v.title,
        severity: v.severity,
        category: v.category,
        url: v.url,
        description: v.description,
        solution: v.solution,
        status: v.status,
        createdAt: v.createdAt
      }))
    }, null, 2);
    contentType = 'application/json';
    filename = `scan-${scan.id}-vulnerabilities.json`;
  } else if (format === 'csv') {
    const headers = ['Title', 'Severity', 'Category', 'URL', 'Status', 'Created'];
    const rows = vulnerabilities.map(v => [
      `"${v.title}"`,
      v.severity,
      v.category || '',
      `"${v.url}"`,
      v.status,
      v.createdAt
    ].join(','));
    content = [headers.join(','), ...rows].join('\n');
    contentType = 'text/csv';
    filename = `scan-${scan.id}-vulnerabilities.csv`;
  } else if (format === 'html') {
    content = generateHTMLReport(scan, vulnerabilities);
    contentType = 'text/html';
    filename = `scan-${scan.id}-report.html`;
  }

  res.setHeader('Content-Type', contentType);
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(content);
}));

// @route   GET /api/reports/compliance/:scanId
// @desc    Generate compliance report
// @access  Private
router.get('/compliance/:scanId', authenticateToken, [
  param('scanId').isUUID().withMessage('Invalid scan ID'),
  query('standard').optional().isIn(['owasp', 'pci-dss', 'hipaa', 'all']).withMessage('Standard must be owasp, pci-dss, hipaa, or all')
], validateRequest, asyncHandler(async (req, res) => {
  const { scanId } = req.params;
  const { standard = 'all' } = req.query;
  const userId = req.user.id;
  const userRole = req.user.role;

  const scan = await Scan.findByPk(scanId, {
    include: [{ model: Vulnerability, as: 'vulnerabilities' }]
  });

  if (!scan) {
    return res.status(404).json({ success: false, message: 'Scan not found' });
  }

  if (userRole !== 'admin' && scan.userId !== userId) {
    return res.status(403).json({ success: false, message: 'Access denied' });
  }

  const vulnerabilities = scan.vulnerabilities || [];
  
  const complianceResults = generateComplianceReport(vulnerabilities, standard);
  
  res.json({ success: true, data: complianceResults });
}));

// Helper functions
const generateHTMLReport = (scan, vulnerabilities) => {
  const severityColors = { critical: '#dc3545', high: '#fd7e14', medium: '#ffc107', low: '#17a2b8' };
  
  return `
<!DOCTYPE html>
<html>
<head>
  <title>Security Scan Report - ${scan.name}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; }
    h1 { color: #333; }
    .summary { background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
    .vuln { border-left: 4px solid #ccc; padding: 15px; margin-bottom: 15px; background: #fff; }
    .vuln.critical { border-color: ${severityColors.critical}; }
    .vuln.high { border-color: ${severityColors.high}; }
    .vuln.medium { border-color: ${severityColors.medium}; }
    .vuln.low { border-color: ${severityColors.low}; }
    .severity { display: inline-block; padding: 3px 8px; border-radius: 3px; color: white; font-weight: bold; }
    .critical { background: ${severityColors.critical}; }
    .high { background: ${severityColors.high}; }
    .medium { background: ${severityColors.medium}; color: #333; }
    .low { background: ${severityColors.low}; }
  </style>
</head>
<body>
  <h1>Security Scan Report</h1>
  <div class="summary">
    <h2>Scan Summary</h2>
    <p><strong>Name:</strong> ${scan.name}</p>
    <p><strong>Target:</strong> ${scan.target}</p>
    <p><strong>Status:</strong> ${scan.status}</p>
    <p><strong>Date:</strong> ${new Date(scan.createdAt).toLocaleString()}</p>
  </div>
  
  <h2>Vulnerabilities (${vulnerabilities.length})</h2>
  ${vulnerabilities.map(v => `
    <div class="vuln ${v.severity}">
      <span class="severity ${v.severity}">${v.severity.toUpperCase()}</span>
      <h3>${v.title}</h3>
      <p><strong>Category:</strong> ${v.category || 'N/A'}</p>
      <p><strong>URL:</strong> ${v.url}</p>
      <p>${v.description}</p>
      <p><strong>Solution:</strong> ${v.solution}</p>
    </div>
  `).join('')}
</body>
</html>
  `.trim();
};

const generateComplianceReport = (vulnerabilities, standard) => {
  const owaspCategories = {
    'sql-injection': 'A03:2021 – Injection',
    'xss': 'A03:2021 – Injection',
    'command-injection': 'A03:2021 – Injection',
    'path-traversal': 'A01:2021 – Broken Access Control',
    'idor': 'A01:2021 – Broken Access Control',
    'ssrf': 'A10:2021 – Server-Side Request Forgery',
    'jwt': 'A02:2021 – Cryptographic Failures',
    'ssti': 'A03:2021 – Injection',
    'security-misconfiguration': 'A05:2021 – Security Misconfiguration',
    'sensitive-data': 'A02:2021 – Cryptographic Failures'
  };

  const pciDssCategories = [
    'sql-injection', 'xss', 'sensitive-data', 'jwt', 'security-misconfiguration'
  ];

  const hipaaCategories = [
    'sql-injection', 'xss', 'sensitive-data', 'security-misconfiguration'
  ];

  const results = { standard: standard === 'all' ? 'Multiple' : standard.toUpperCase(), checks: [], passed: 0, failed: 0 };

  if (standard === 'all' || standard === 'owasp') {
    const owaspResults = vulnerabilities.map(v => ({
      standard: 'OWASP Top 10 2021',
      vulnerability: v.title,
      category: v.category,
      mapping: owaspCategories[v.category] || 'Unknown',
      status: 'FAIL',
      severity: v.severity
    }));
    results.checks.push(...owaspResults);
    results.failed += owaspResults.length;
  }

  if (standard === 'all' || standard === 'pci-dss') {
    const pciResults = vulnerabilities
      .filter(v => pciDssCategories.includes(v.category))
      .map(v => ({
        standard: 'PCI-DSS',
        vulnerability: v.title,
        category: v.category,
        mapping: 'Requirement 6.5.10',
        status: 'FAIL',
        severity: v.severity
      }));
    results.checks.push(...pciResults);
    results.failed += pciResults.length;
  }

  if (standard === 'all' || standard === 'hipaa') {
    const hipaaResults = vulnerabilities
      .filter(v => hipaaCategories.includes(v.category))
      .map(v => ({
        standard: 'HIPAA',
        vulnerability: v.title,
        category: v.category,
        mapping: '164.312(a)',
        status: 'FAIL',
        severity: v.severity
      }));
    results.checks.push(...hipaaResults);
    results.failed += hipaaResults.length;
  }

  return results;
};

module.exports = router;
