const express = require('express');
const { body, param, query } = require('express-validator');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { validateRequest, asyncHandler } = require('../middleware/errorHandler');
const { logger } = require('../utils/logger');
const {
  scanContainerImage,
  assessCloudSecurityPosture,
  sendToSIEM,
  createPatchTask,
  trackSLACompliance,
  createRiskRegister,
  evaluatePolicy,
  threatHunt,
  runPenetrationTest,
  assessZeroTrust
} = require('../services/enterpriseFeatures');
const { Vulnerability, Scan } = require('../models');

const router = express.Router();

router.get('/container/scan', authenticateToken, [
  query('image').notEmpty().withMessage('Image name required')
], validateRequest, asyncHandler(async (req, res) => {
  const { image } = req.query;
  const results = await scanContainerImage(image);
  res.json({ success: true, data: results });
}));

router.get('/cloud/cspm', authenticateToken, [
  query('provider').isIn(['aws', 'azure', 'gcp']).withMessage('Invalid provider')
], validateRequest, asyncHandler(async (req, res) => {
  const { provider } = req.query;
  const results = await assessCloudSecurityPosture(provider, []);
  res.json({ success: true, data: results });
}));

router.post('/siem/send', authenticateToken, requireRole(['admin']), [
  body('type').notEmpty().withMessage('Event type required'),
  body('data').isObject().withMessage('Event data required')
], validateRequest, asyncHandler(async (req, res) => {
  const siemConfig = { enabled: true, type: 'splunk', endpoint: process.env.SIEM_ENDPOINT, apiKey: process.env.SIEM_API_KEY };
  const result = await sendToSIEM(siemConfig, req.body);
  res.json({ success: true, data: result });
}));

router.post('/patch/create', authenticateToken, [
  body('vulnerabilityId').isUUID().withMessage('Valid vulnerability ID required'),
  body('dueDate').isISO8601().withMessage('Valid due date required')
], validateRequest, asyncHandler(async (req, res) => {
  const { vulnerabilityId, dueDate } = req.body;
  const vulnerability = await Vulnerability.findByPk(vulnerabilityId);
  if (!vulnerability) {
    return res.status(404).json({ success: false, message: 'Vulnerability not found' });
  }
  const task = await createPatchTask(vulnerability, dueDate);
  res.json({ success: true, data: task });
}));

router.get('/sla/compliance', authenticateToken, asyncHandler(async (req, res) => {
  const vulnerabilities = await Vulnerability.findAll({ where: { status: { [require('sequelize').Op.ne]: 'false_positive' } } });
  const compliance = await trackSLACompliance(vulnerabilities);
  res.json({ success: true, data: compliance });
}));

router.post('/risk-register', authenticateToken, [
  body('name').notEmpty().withMessage('Risk name required'),
  body('category').notEmpty().withMessage('Category required'),
  body('likelihood').isInt({ min: 1, max: 5 }).withMessage('Likelihood must be 1-5'),
  body('impact').isInt({ min: 1, max: 5 }).withMessage('Impact must be 1-5')
], validateRequest, asyncHandler(async (req, res) => {
  const { name, category, likelihood, impact } = req.body;
  const vulnerabilities = await Vulnerability.findAll({ limit: 5 });
  const risk = await createRiskRegister(name, category, likelihood, impact, vulnerabilities);
  res.json({ success: true, data: risk });
}));

router.post('/policy/evaluate', authenticateToken, requireRole(['admin', 'analyst']), [
  body('policy').isObject().withMessage('Policy object required'),
  body('target').isObject().withMessage('Target object required')
], validateRequest, asyncHandler(async (req, res) => {
  const { policy, target } = req.body;
  const results = await evaluatePolicy(policy, target);
  res.json({ success: true, data: results });
}));

router.post('/threat-hunt', authenticateToken, [
  body('ioc').notEmpty().withMessage('IOC required'),
  query('timeframe').optional().isInt({ min: 1, max: 365 })
], validateRequest, asyncHandler(async (req, res) => {
  const { ioc } = req.body;
  const timeframe = parseInt(req.query.timeframe) || 30;
  const results = await threatHunt(ioc, timeframe);
  res.json({ success: true, data: results });
}));

router.post('/pentest/start', authenticateToken, requireRole(['admin']), [
  body('target').notEmpty().withMessage('Target required'),
  body('scope').optional().isArray()
], validateRequest, asyncHandler(async (req, res) => {
  const { target, scope } = req.body;
  const results = await runPenetrationTest(target, scope || []);
  res.json({ success: true, data: results });
}));

router.get('/zero-trust', authenticateToken, [
  query('target').notEmpty().withMessage('Target required')
], validateRequest, asyncHandler(async (req, res) => {
  const { target } = req.query;
  const assessment = await assessZeroTrust(target);
  res.json({ success: true, data: assessment });
}));

module.exports = router;
