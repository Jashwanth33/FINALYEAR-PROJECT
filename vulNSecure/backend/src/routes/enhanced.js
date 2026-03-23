const express = require('express');
const { body, param } = require('express-validator');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { validateRequest, asyncHandler } = require('../middleware/errorHandler');
const { logger } = require('../utils/logger');
const { Scan, Vulnerability, ScheduledScan } = require('../models');
const { analyzeVulnerability } = require('../services/aiAnalysis');
const { generatePDFReport } = require('../services/pdfReport');
const { createScheduledScan, updateScheduledScan, deleteScheduledScan } = require('../services/scheduledScans');

const router = express.Router();

// ============================================================
// AI ANALYSIS
// ============================================================

router.post('/ai-analyze', authenticateToken, [
  body('vulnerabilityId').isUUID().withMessage('Valid vulnerability ID required')
], validateRequest, asyncHandler(async (req, res) => {
  const { vulnerabilityId } = req.body;
  
  const vulnerability = await Vulnerability.findByPk(vulnerabilityId);
  
  if (!vulnerability) {
    return res.status(404).json({
      success: false,
      message: 'Vulnerability not found'
    });
  }
  
  const analysis = await analyzeVulnerability(vulnerability);
  
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

// ============================================================
// PDF REPORT GENERATION
// ============================================================

router.get('/report/:scanId', authenticateToken, asyncHandler(async (req, res) => {
  const { scanId } = req.params;
  
  const result = await generatePDFReport(scanId, req.user.id);
  
  res.download(result.filePath, result.fileName);
}));

router.post('/report/generate', authenticateToken, [
  body('scanId').isUUID().withMessage('Valid scan ID required')
], validateRequest, asyncHandler(async (req, res) => {
  const { scanId } = req.body;
  
  const result = await generatePDFReport(scanId, req.user.id);
  
  res.json({
    success: true,
    message: 'Report generated successfully',
    data: {
      fileName: result.fileName,
      fileSize: result.fileSize,
      summary: result.summary,
      downloadUrl: '/api/enhanced/report/' + scanId
    }
  });
}));

// ============================================================
// SCHEDULED SCANS
// ============================================================

router.get('/scheduled', authenticateToken, asyncHandler(async (req, res) => {
  const scheduled = await ScheduledScan.findAll({
    where: { userId: req.user.id },
    order: [['createdAt', 'DESC']]
  });
  
  res.json({
    success: true,
    data: { scheduled }
  });
}));

router.post('/scheduled', authenticateToken, [
  body('name').isLength({ min: 1 }).withMessage('Name is required'),
  body('target').isLength({ min: 1 }).withMessage('Target is required'),
  body('frequency').isIn(['daily', 'weekly', 'monthly']).withMessage('Invalid frequency'),
  body('time').matches(/^\d{2}:\d{2}$/).withMessage('Time must be HH:MM format')
], validateRequest, asyncHandler(async (req, res) => {
  const { name, target, frequency, dayOfWeek, time, type } = req.body;
  
  const scheduled = await createScheduledScan({
    userId: req.user.id,
    name,
    target,
    frequency,
    dayOfWeek,
    time,
    type: type || 'web'
  });
  
  res.status(201).json({
    success: true,
    message: 'Scheduled scan created',
    data: { scheduled }
  });
}));

router.put('/scheduled/:id', authenticateToken, [
  param('id').isUUID().withMessage('Invalid ID')
], validateRequest, asyncHandler(async (req, res) => {
  const scheduled = await updateScheduledScan(req.params.id, req.body);
  
  res.json({
    success: true,
    message: 'Scheduled scan updated',
    data: { scheduled }
  });
}));

router.delete('/scheduled/:id', authenticateToken, asyncHandler(async (req, res) => {
  await deleteScheduledScan(req.params.id);
  
  res.json({
    success: true,
    message: 'Scheduled scan deleted'
  });
}));

// ============================================================
// SCAN COMPARISON
// ============================================================

router.post('/compare', authenticateToken, [
  body('scanId1').isUUID().withMessage('Valid scan ID required'),
  body('scanId2').isUUID().withMessage('Valid scan ID required')
], validateRequest, asyncHandler(async (req, res) => {
  const { scanId1, scanId2 } = req.body;
  
  const vulns1 = await Vulnerability.findAll({ where: { scanId: scanId1 } });
  const vulns2 = await Vulnerability.findAll({ where: { scanId: scanId2 } });
  
  const vulns1Keys = new Set(vulns1.map(v => v.url + v.title));
  const vulns2Keys = new Set(vulns2.map(v => v.url + v.title));
  
  const newVulns = vulns2.filter(v => !vulns1Keys.has(v.url + v.title));
  const fixedVulns = vulns1.filter(v => !vulns2Keys.has(v.url + v.title));
  const persistentVulns = vulns2.filter(v => vulns1Keys.has(v.url + v.title));
  
  res.json({
    success: true,
    data: {
      comparison: {
        new: newVulns.length,
        fixed: fixedVulns.length,
        persistent: persistentVulns.length
      },
      details: {
        newVulns: newVulns.map(v => ({ title: v.title, severity: v.severity, url: v.url })),
        fixedVulns: fixedVulns.map(v => ({ title: v.title, severity: v.severity, url: v.url })),
        persistentVulns: persistentVulns.map(v => ({ title: v.title, severity: v.severity, url: v.url }))
      }
    }
  });
}));

module.exports = router;
