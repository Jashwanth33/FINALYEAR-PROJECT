const express = require('express');
const { body, param } = require('express-validator');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { validateRequest, asyncHandler } = require('../middleware/errorHandler');
const { logger } = require('../utils/logger');
const {
  performAuthenticatedScan,
  enumerateSubdomains,
  scanPorts,
  enumerateDNS,
  analyzeSSL,
  analyzeWithAI,
  sendNotifications,
  detectTechnologies
} = require('../services/proFeatures');

const router = express.Router();

// @route   POST /api/pro/subdomains
// @desc    Enumerate subdomains
// @access  Private
router.post('/subdomains', authenticateToken, [
  body('domain').isLength({ min: 1 }).withMessage('Domain is required')
], validateRequest, asyncHandler(async (req, res) => {
  const { domain } = req.body;
  
  logger.info('Starting subdomain enumeration for: ' + domain);
  
  const results = await enumerateSubdomains(domain);
  
  res.json({
    success: true,
    data: results
  });
}));

// @route   POST /api/pro/ports
// @desc    Scan ports
// @access  Private
router.post('/ports', authenticateToken, [
  body('hostname').isLength({ min: 1 }).withMessage('Hostname is required')
], validateRequest, asyncHandler(async (req, res) => {
  const { hostname } = req.body;
  
  logger.info('Starting port scan for: ' + hostname);
  
  const results = await scanPorts(hostname);
  
  res.json({
    success: true,
    data: results
  });
}));

// @route   POST /api/pro/dns
// @desc    DNS enumeration
// @access  Private
router.post('/dns', authenticateToken, [
  body('domain').isLength({ min: 1 }).withMessage('Domain is required')
], validateRequest, asyncHandler(async (req, res) => {
  const { domain } = req.body;
  
  const results = await enumerateDNS(domain);
  
  res.json({
    success: true,
    data: results
  });
}));

// @route   POST /api/pro/ssl
// @desc    SSL/TLS analysis
// @access  Private
router.post('/ssl', authenticateToken, [
  body('hostname').isLength({ min: 1 }).withMessage('Hostname is required')
], validateRequest, asyncHandler(async (req, res) => {
  const { hostname } = req.body;
  
  const results = await analyzeSSL(hostname);
  
  res.json({
    success: true,
    data: results
  });
}));

// @route   POST /api/pro/technologies
// @desc    Detect technologies
// @access  Private
router.post('/technologies', authenticateToken, [
  body('url').isLength({ min: 1 }).withMessage('URL is required')
], validateRequest, asyncHandler(async (req, res) => {
  const { url } = req.body;
  
  const results = await detectTechnologies(url);
  
  res.json({
    success: true,
    data: results
  });
}));

// @route   POST /api/pro/ai-analyze
// @desc    AI-powered vulnerability analysis
// @access  Private
router.post('/ai-analyze', authenticateToken, [
  body('vulnerabilityId').isUUID().withMessage('Valid vulnerability ID required')
], validateRequest, asyncHandler(async (req, res) => {
  const { vulnerabilityId } = req.body;
  const { Vulnerability } = require('../models');
  
  const vulnerability = await Vulnerability.findByPk(vulnerabilityId);
  
  if (!vulnerability) {
    return res.status(404).json({
      success: false,
      message: 'Vulnerability not found'
    });
  }
  
  const analysis = await analyzeWithAI(vulnerability);
  
  res.json({
    success: true,
    data: {
      vulnerability: {
        id: vulnerability.id,
        title: vulnerability.title,
        severity: vulnerability.severity,
        category: vulnerability.category
      },
      analysis
    }
  });
}));

// @route   POST /api/pro/scan-with-auth
// @desc    Authenticated scan
// @access  Private (admin/analyst only)
router.post('/scan-with-auth', authenticateToken, requireRole(['admin', 'analyst']), [
  body('target').isLength({ min: 1 }).withMessage('Target URL required'),
  body('loginUrl').isLength({ min: 1 }).withMessage('Login URL required'),
  body('username').isLength({ min: 1 }).withMessage('Username required'),
  body('password').isLength({ min: 1 }).withMessage('Password required')
], validateRequest, asyncHandler(async (req, res) => {
  const { target, loginUrl, username, password } = req.body;
  const userId = req.user.id;
  const { Scan } = require('../models');
  
  // Create scan record
  const scan = await Scan.create({
    userId,
    name: 'Authenticated Scan: ' + target,
    target,
    type: 'web',
    status: 'running',
    configuration: { authenticated: true }
  });
  
  // Start async scan
  performAuthenticatedScan(target, scan.id, { loginUrl, username, password })
    .then(async (vulnerabilities) => {
      await scan.update({ 
        status: 'completed', 
        progress: 100, 
        endTime: new Date() 
      });
      logger.info('Authenticated scan completed: ' + vulnerabilities.length + ' vulnerabilities');
    })
    .catch(async (error) => {
      await scan.update({ 
        status: 'failed', 
        errorMessage: error.message, 
        endTime: new Date() 
      });
      logger.error('Authenticated scan failed: ' + error.message);
    });
  
  res.status(201).json({
    success: true,
    message: 'Authenticated scan started',
    data: { scan }
  });
}));

module.exports = router;
