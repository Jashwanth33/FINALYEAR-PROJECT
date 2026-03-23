const express = require('express');
const { body } = require('express-validator');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { validateRequest, asyncHandler } = require('../middleware/errorHandler');
const {
  exportToCSV,
  exportToJSON,
  exportToExcel,
  logActivity,
  getAuditLogs,
  compareScans,
  updateRemediation,
  getRemediationStats,
  startBulkScan,
  createCustomRule,
  getCustomRules,
  generateResetToken,
  resetPassword,
  generate2FASecret,
  updateRateLimit,
  getRateLimitConfig
} = require('../services/completeNewFeatures');

const router = express.Router();

// ============================================================
// EXPORT OPTIONS
// ============================================================

router.get('/export/csv/:scanId', authenticateToken, asyncHandler(async (req, res) => {
  const csv = await exportToCSV(req.params.scanId);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename=scan-${req.params.scanId}.csv`);
  res.send(csv);
}));

router.get('/export/json/:scanId', authenticateToken, asyncHandler(async (req, res) => {
  const json = await exportToJSON(req.params.scanId);
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename=scan-${req.params.scanId}.json`);
  res.send(json);
}));

router.get('/export/excel/:scanId', authenticateToken, asyncHandler(async (req, res) => {
  const data = await exportToExcel(req.params.scanId);
  res.setHeader('Content-Type', 'application/vnd.ms-excel');
  res.setHeader('Content-Disposition', `attachment; filename=scan-${req.params.scanId}.xls`);
  res.send(data);
}));

// ============================================================
// AUDIT LOG
// ============================================================

router.get('/audit', authenticateToken, requireRole(['admin']), asyncHandler(async (req, res) => {
  const logs = await getAuditLogs(null, parseInt(req.query.limit) || 50);
  res.json({ success: true, data: { logs } });
}));

router.get('/audit/user', authenticateToken, asyncHandler(async (req, res) => {
  const logs = await getAuditLogs(req.user.id, parseInt(req.query.limit) || 50);
  res.json({ success: true, data: { logs } });
}));

// ============================================================
// SCAN COMPARISON
// ============================================================

router.post('/compare', authenticateToken, [
  body('scanId1').isUUID().withMessage('Valid scan ID required'),
  body('scanId2').isUUID().withMessage('Valid scan ID required')
], validateRequest, asyncHandler(async (req, res) => {
  const result = await compareScans(req.body.scanId1, req.body.scanId2);
  res.json({ success: true, data: result });
}));

// ============================================================
// REMEDIATION TRACKING
// ============================================================

router.get('/remediation/stats', authenticateToken, asyncHandler(async (req, res) => {
  const stats = await getRemediationStats(req.user.id);
  res.json({ success: true, data: stats });
}));

router.put('/remediation/:id', authenticateToken, [
  body('status').isIn(['open', 'in_progress', 'fixed', 'accepted']).withMessage('Invalid status')
], validateRequest, asyncHandler(async (req, res) => {
  const vuln = await updateRemediation(req.params.id, { ...req.body, assignedBy: req.user.id });
  res.json({ success: true, data: { vulnerability: vuln } });
}));

// ============================================================
// BULK SCANNING
// ============================================================

router.post('/bulk', authenticateToken, [
  body('targets').isArray({ min: 1 }).withMessage('Targets array required')
], validateRequest, asyncHandler(async (req, res) => {
  const result = await startBulkScan(req.body.targets, req.user.id);
  res.json({ success: true, data: { results: result } });
}));

// ============================================================
// CUSTOM RULES
// ============================================================

router.get('/rules', authenticateToken, asyncHandler(async (req, res) => {
  const rules = await getCustomRules(req.user.id);
  res.json({ success: true, data: { rules } });
}));

router.post('/rules', authenticateToken, [
  body('name').isLength({ min: 1 }).withMessage('Name required'),
  body('pattern').isLength({ min: 1 }).withMessage('Pattern required')
], validateRequest, asyncHandler(async (req, res) => {
  const rule = await createCustomRule(req.user.id, req.body);
  res.status(201).json({ success: true, data: { rule } });
}));

// ============================================================
// PASSWORD RESET
// ============================================================

router.post('/password/reset-request', [
  body('email').isEmail().withMessage('Valid email required')
], validateRequest, asyncHandler(async (req, res) => {
  const result = await generateResetToken(req.body.email);
  res.json({ success: true, message: 'Reset token generated', data: { token: result.token } });
}));

router.post('/password/reset', [
  body('token').isLength({ min: 1 }).withMessage('Token required'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
], validateRequest, asyncHandler(async (req, res) => {
  await resetPassword(req.body.token, req.body.password);
  res.json({ success: true, message: 'Password reset successful' });
}));

// ============================================================
// TWO-FACTOR AUTH
// ============================================================

router.post('/2fa/setup', authenticateToken, asyncHandler(async (req, res) => {
  const result = await generate2FASecret(req.user.id);
  res.json({ success: true, data: result });
}));

// ============================================================
// RATE LIMITING
// ============================================================

router.get('/rate-limit', authenticateToken, requireRole(['admin']), asyncHandler(async (req, res) => {
  const config = getRateLimitConfig();
  res.json({ success: true, data: config });
}));

router.put('/rate-limit', authenticateToken, requireRole(['admin']), asyncHandler(async (req, res) => {
  const config = updateRateLimit(req.body.type, req.body.config);
  res.json({ success: true, data: config });
}));

module.exports = router;
