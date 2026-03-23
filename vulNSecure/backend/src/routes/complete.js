const express = require('express');
const { body } = require('express-validator');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { validateRequest, asyncHandler } = require('../middleware/errorHandler');
const {
  interceptRequest,
  repeatRequest,
  fuzzEndpoint,
  analyzeToken,
  encodeDecode,
  generateCIConfig,
  checkCompliance,
  addComment,
  assignVulnerability,
  checkDarkWebLeaks
} = require('../services/completeFeatures');

const router = express.Router();

// ============================================================
// BURP SUITE FEATURES
// ============================================================

router.post('/intercept', authenticateToken, [
  body('url').isLength({ min: 1 }).withMessage('URL required'),
  body('method').optional().isIn(['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
], validateRequest, asyncHandler(async (req, res) => {
  const { url, method, headers, body } = req.body;
  const result = await interceptRequest(url, method, headers, body);
  res.json({ success: true, data: result });
}));

router.post('/repeater', authenticateToken, [
  body('url').isLength({ min: 1 }).withMessage('URL required'),
  body('times').optional().isInt({ min: 1, max: 100 })
], validateRequest, asyncHandler(async (req, res) => {
  const { url, method, headers, body, times } = req.body;
  const result = await repeatRequest(url, method, headers, body, times || 5);
  res.json({ success: true, data: result });
}));

router.post('/intruder', authenticateToken, [
  body('url').isLength({ min: 1 }).withMessage('URL required'),
  body('param').isLength({ min: 1 }).withMessage('Parameter required'),
  body('payloads').isArray({ min: 1 }).withMessage('Payloads required')
], validateRequest, asyncHandler(async (req, res) => {
  const { url, param, payloads, method } = req.body;
  const result = await fuzzEndpoint(url, param, payloads, method);
  res.json({ success: true, data: result });
}));

router.post('/sequencer', authenticateToken, [
  body('url').isLength({ min: 1 }).withMessage('URL required')
], validateRequest, asyncHandler(async (req, res) => {
  const { url, iterations } = req.body;
  const result = await analyzeToken(url, iterations || 10);
  res.json({ success: true, data: result });
}));

router.post('/decode', authenticateToken, [
  body('input').isLength({ min: 1 }).withMessage('Input required'),
  body('type').isLength({ min: 1 }).withMessage('Type required')
], validateRequest, asyncHandler(async (req, res) => {
  const { input, type } = req.body;
  const result = encodeDecode(input, type);
  res.json({ success: true, data: { result, type } });
}));

// ============================================================
// CI/CD INTEGRATION
// ============================================================

router.post('/cicd/config', authenticateToken, [
  body('platform').isIn(['github', 'gitlab', 'jenkins']).withMessage('Invalid platform'),
  body('target').isLength({ min: 1 }).withMessage('Target required')
], validateRequest, asyncHandler(async (req, res) => {
  const { platform, target } = req.body;
  const config = generateCIConfig(platform, target);
  res.json({ success: true, data: { platform, config } });
}));

// ============================================================
// COMPLIANCE
// ============================================================

router.post('/compliance', authenticateToken, [
  body('scanId').isUUID().withMessage('Valid scan ID required'),
  body('framework').isIn(['pci-dss', 'hipaa', 'owasp', 'soc2', 'gdpr']).withMessage('Invalid framework')
], validateRequest, asyncHandler(async (req, res) => {
  const { scanId, framework } = req.body;
  const result = await checkCompliance(scanId, framework);
  res.json({ success: true, data: result });
}));

// ============================================================
// TEAM COLLABORATION
// ============================================================

router.post('/comments', authenticateToken, [
  body('vulnerabilityId').isUUID().withMessage('Valid vulnerability ID required'),
  body('comment').isLength({ min: 1 }).withMessage('Comment required')
], validateRequest, asyncHandler(async (req, res) => {
  const { vulnerabilityId, comment } = req.body;
  const comments = await addComment(vulnerabilityId, req.user.id, comment);
  res.json({ success: true, data: { comments } });
}));

router.post('/assign', authenticateToken, requireRole(['admin', 'analyst']), [
  body('vulnerabilityId').isUUID().withMessage('Valid vulnerability ID required'),
  body('assigneeId').isUUID().withMessage('Valid assignee ID required')
], validateRequest, asyncHandler(async (req, res) => {
  const { vulnerabilityId, assigneeId } = req.body;
  const vuln = await assignVulnerability(vulnerabilityId, assigneeId);
  res.json({ success: true, data: { vulnerability: vuln } });
}));

// ============================================================
// DARK WEB MONITORING
// ============================================================

router.post('/darkweb', authenticateToken, [
  body('domain').isLength({ min: 1 }).withMessage('Domain required')
], validateRequest, asyncHandler(async (req, res) => {
  const { domain } = req.body;
  const result = await checkDarkWebLeaks(domain);
  res.json({ success: true, data: result });
}));

module.exports = router;
