const express = require('express');
const { body } = require('express-validator');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { validateRequest, asyncHandler } = require('../middleware/errorHandler');
const { ScheduledScan } = require('../models');
const {
  generatePDFReport,
  sendEmailNotification,
  createSchedule,
  getDashboardStats
} = require('../services/newFeatures');

const router = express.Router();

// ============================================================
// PDF REPORT
// ============================================================

router.get('/report/:scanId', authenticateToken, asyncHandler(async (req, res) => {
  const result = await generatePDFReport(req.params.scanId, req.user.id);
  res.download(result.filePath, result.fileName);
}));

router.post('/report/generate', authenticateToken, [
  body('scanId').isUUID().withMessage('Valid scan ID required')
], validateRequest, asyncHandler(async (req, res) => {
  const result = await generatePDFReport(req.body.scanId, req.user.id);
  res.json({
    success: true,
    message: 'Report generated',
    data: { fileName: result.fileName, summary: result.summary }
  });
}));

// ============================================================
// NOTIFICATIONS
// ============================================================

router.post('/notify', authenticateToken, [
  body('type').isIn(['vulnerability_found', 'scan_complete', 'weekly_summary']).withMessage('Invalid type')
], validateRequest, asyncHandler(async (req, res) => {
  const result = await sendEmailNotification(req.body.type, { ...req.body.data, userId: req.user.id });
  res.json({ success: true, data: result });
}));

// ============================================================
// SCHEDULED SCANS
// ============================================================

router.get('/schedules', authenticateToken, asyncHandler(async (req, res) => {
  const schedules = await ScheduledScan.findAll({
    where: { userId: req.user.id },
    order: [['createdAt', 'DESC']]
  });
  res.json({ success: true, data: { schedules } });
}));

router.post('/schedules', authenticateToken, [
  body('name').isLength({ min: 1 }).withMessage('Name required'),
  body('target').isLength({ min: 1 }).withMessage('Target required'),
  body('frequency').isIn(['daily', 'weekly', 'monthly']).withMessage('Invalid frequency'),
  body('time').matches(/^\d{2}:\d{2}$/).withMessage('Time must be HH:MM')
], validateRequest, asyncHandler(async (req, res) => {
  const schedule = await createSchedule({ ...req.body, userId: req.user.id });
  res.status(201).json({ success: true, message: 'Schedule created', data: { schedule } });
}));

router.delete('/schedules/:id', authenticateToken, asyncHandler(async (req, res) => {
  await ScheduledScan.destroy({ where: { id: req.params.id, userId: req.user.id } });
  res.json({ success: true, message: 'Schedule deleted' });
}));

// ============================================================
// DASHBOARD STATS
// ============================================================

router.get('/dashboard', authenticateToken, asyncHandler(async (req, res) => {
  const stats = await getDashboardStats(req.user.id);
  res.json({ success: true, data: stats });
}));

module.exports = router;
