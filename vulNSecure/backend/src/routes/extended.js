const express = require('express');
const { body, param, query } = require('express-validator');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { validateRequest, asyncHandler } = require('../middleware/errorHandler');
const { logger } = require('../utils/logger');
const {
  webhookManager,
  checkMalwarePhishing,
  checkDNSBL,
  scanForSecrets,
  exportData,
  importData,
  RateLimitTracker,
  generateSecurityReport,
  detectAnomalies
} = require('../services/extendedFeatures');
const { Scan, Vulnerability } = require('../models');

const router = express.Router();

router.post('/webhooks', authenticateToken, requireRole(['admin']), [
  body('url').isURL().withMessage('Valid URL required'),
  body('events').isArray().withMessage('Events array required')
], validateRequest, asyncHandler(async (req, res) => {
  const { url, events, secret } = req.body;
  const id = `wh_${Date.now()}`;
  const webhook = await webhookManager.registerWebhook(id, url, events, secret);
  res.json({ success: true, data: webhook });
}));

router.get('/webhooks', authenticateToken, requireRole(['admin']), asyncHandler(async (req, res) => {
  const webhooks = webhookManager.listWebhooks();
  res.json({ success: true, data: webhooks });
}));

router.delete('/webhooks/:id', authenticateToken, requireRole(['admin']), asyncHandler(async (req, res) => {
  const { id } = req.params;
  webhookManager.deleteWebhook(id);
  res.json({ success: true, message: 'Webhook deleted' });
}));

router.get('/malware-check', authenticateToken, [
  query('url').isURL().withMessage('Valid URL required')
], validateRequest, asyncHandler(async (req, res) => {
  const { url } = req.query;
  const results = await checkMalwarePhishing(url);
  res.json({ success: true, data: results });
}));

router.get('/dnsbl-check', authenticateToken, [
  query('ip').isIP().withMessage('Valid IP required')
], validateRequest, asyncHandler(async (req, res) => {
  const { ip } = req.query;
  const results = await checkDNSBL(ip);
  res.json({ success: true, data: results });
}));

router.get('/secret-scan', authenticateToken, [
  query('target').isURL().withMessage('Valid target URL required')
], validateRequest, asyncHandler(async (req, res) => {
  const { target } = req.query;
  const secrets = await scanForSecrets(target);
  res.json({ success: true, data: secrets });
}));

router.get('/export', authenticateToken, [
  query('format').optional().isIn(['json', 'csv']).withMessage('Format must be json or csv')
], validateRequest, asyncHandler(async (req, res) => {
  const { format = 'json' } = req.query;
  const data = await exportData(req.user.id, format);
  
  if (format === 'json') {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="vulnsecure-export-${Date.now()}.json"`);
  } else {
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="vulnsecure-export-${Date.now()}.csv"`);
  }
  
  res.send(data);
}));

router.post('/import', authenticateToken, requireRole(['admin']), [
  body('data').notEmpty().withMessage('Data required'),
  body('format').optional().isIn(['json']).withMessage('Format must be json')
], validateRequest, asyncHandler(async (req, res) => {
  const { data, format = 'json' } = req.body;
  const results = await importData(req.user.id, data, format);
  res.json({ success: true, data: results });
}));

router.get('/rate-limit/stats', authenticateToken, requireRole(['admin']), asyncHandler(async (req, res) => {
  const ip = req.ip;
  const stats = RateLimitTracker.getStats(ip);
  res.json({ success: true, data: stats });
}));

router.get('/security-report/:scanId', authenticateToken, asyncHandler(async (req, res) => {
  const { scanId } = req.params;
  
  const scan = await Scan.findByPk(scanId, {
    include: [{ model: Vulnerability, as: 'vulnerabilities' }]
  });
  
  if (!scan) {
    return res.status(404).json({ success: false, message: 'Scan not found' });
  }
  
  const report = generateSecurityReport(scan, scan.vulnerabilities || []);
  res.json({ success: true, data: report });
}));

router.get('/anomaly-detection', authenticateToken, [
  query('target').isURL().withMessage('Valid target required')
], validateRequest, asyncHandler(async (req, res) => {
  const { target } = req.query;
  const anomalies = await detectAnomalies(target);
  res.json({ success: true, data: anomalies });
}));

module.exports = router;
