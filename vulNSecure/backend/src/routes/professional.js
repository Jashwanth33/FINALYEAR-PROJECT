const express = require('express');
const { body, param } = require('express-validator');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { validateRequest, asyncHandler } = require('../middleware/errorHandler');
const { Scan, Vulnerability, Asset } = require('../models');
const {
  performAuthenticatedScan,
  testGraphQL,
  testCloudSecurity,
  sendSlackNotification,
  sendTeamsNotification,
  sendWebhookNotification,
  discoverAssets,
  testJWTSecurity,
  testDNSSecurity,
  testSSLDeep,
  detectWAF
} = require('../services/professionalFeatures');

const router = express.Router();

// ============================================================
// AUTHENTICATED SCAN
// ============================================================

router.post('/auth-scan', authenticateToken, requireRole(['admin', 'analyst']), [
  body('target').isLength({ min: 1 }).withMessage('Target required'),
  body('loginUrl').isLength({ min: 1 }).withMessage('Login URL required'),
  body('username').isLength({ min: 1 }).withMessage('Username required'),
  body('password').isLength({ min: 1 }).withMessage('Password required')
], validateRequest, asyncHandler(async (req, res) => {
  const { target, loginUrl, username, password } = req.body;
  
  const scan = await Scan.create({
    userId: req.user.id,
    name: 'Authenticated Scan: ' + target,
    target,
    type: 'web',
    status: 'running'
  });
  
  performAuthenticatedScan(target, scan.id, { loginUrl, username, password })
    .then(async () => {
      const vulns = await Vulnerability.findAll({ where: { scanId: scan.id } });
      await scan.update({
        status: 'completed',
        progress: 100,
        endTime: new Date(),
        summary: {
          critical: vulns.filter(v => v.severity === 'critical').length,
          high: vulns.filter(v => v.severity === 'high').length,
          total: vulns.length
        }
      });
    })
    .catch(async (e) => {
      await scan.update({ status: 'failed', errorMessage: e.message });
    });
  
  res.status(201).json({
    success: true,
    message: 'Authenticated scan started',
    data: { scan }
  });
}));

// ============================================================
// GRAPHQL SCAN
// ============================================================

router.post('/graphql', authenticateToken, [
  body('url').isLength({ min: 1 }).withMessage('URL required')
], validateRequest, asyncHandler(async (req, res) => {
  const { url } = req.body;
  
  const scan = await Scan.create({
    userId: req.user.id,
    name: 'GraphQL Scan: ' + url,
    target: url,
    type: 'web',
    status: 'running'
  });
  
  testGraphQL(url, scan.id)
    .then(async () => {
      const vulns = await Vulnerability.findAll({ where: { scanId: scan.id } });
      await scan.update({ status: 'completed', progress: 100, endTime: new Date() });
    })
    .catch(async (e) => {
      await scan.update({ status: 'failed', errorMessage: e.message });
    });
  
  res.status(201).json({
    success: true,
    message: 'GraphQL scan started',
    data: { scan }
  });
}));

// ============================================================
// CLOUD SECURITY SCAN
// ============================================================

router.post('/cloud', authenticateToken, [
  body('target').isLength({ min: 1 }).withMessage('Target required')
], validateRequest, asyncHandler(async (req, res) => {
  const { target } = req.body;
  
  const scan = await Scan.create({
    userId: req.user.id,
    name: 'Cloud Scan: ' + target,
    target,
    type: 'web',
    status: 'running'
  });
  
  testCloudSecurity(target, scan.id)
    .then(async () => {
      await scan.update({ status: 'completed', progress: 100, endTime: new Date() });
    })
    .catch(async (e) => {
      await scan.update({ status: 'failed', errorMessage: e.message });
    });
  
  res.status(201).json({
    success: true,
    message: 'Cloud scan started',
    data: { scan }
  });
}));

// ============================================================
// SLACK NOTIFICATION
// ============================================================

router.post('/notify/slack', authenticateToken, [
  body('webhookUrl').isURL().withMessage('Valid webhook URL required'),
  body('vulnerabilityId').isUUID().withMessage('Valid vulnerability ID required')
], validateRequest, asyncHandler(async (req, res) => {
  const { webhookUrl, vulnerabilityId } = req.body;
  
  const vuln = await Vulnerability.findByPk(vulnerabilityId);
  if (!vuln) {
    return res.status(404).json({ success: false, message: 'Vulnerability not found' });
  }
  
  const result = await sendSlackNotification(webhookUrl, vuln);
  
  res.json({
    success: result,
    message: result ? 'Slack notification sent' : 'Failed to send notification'
  });
}));

// ============================================================
// TEAMS NOTIFICATION
// ============================================================

router.post('/notify/teams', authenticateToken, [
  body('webhookUrl').isURL().withMessage('Valid webhook URL required'),
  body('vulnerabilityId').isUUID().withMessage('Valid vulnerability ID required')
], validateRequest, asyncHandler(async (req, res) => {
  const { webhookUrl, vulnerabilityId } = req.body;
  
  const vuln = await Vulnerability.findByPk(vulnerabilityId);
  if (!vuln) {
    return res.status(404).json({ success: false, message: 'Vulnerability not found' });
  }
  
  const result = await sendTeamsNotification(webhookUrl, vuln);
  
  res.json({
    success: result,
    message: result ? 'Teams notification sent' : 'Failed to send notification'
  });
}));

// ============================================================
// WEBHOOK NOTIFICATION
// ============================================================

router.post('/notify/webhook', authenticateToken, [
  body('webhookUrl').isURL().withMessage('Valid webhook URL required'),
  body('vulnerabilityId').isUUID().withMessage('Valid vulnerability ID required')
], validateRequest, asyncHandler(async (req, res) => {
  const { webhookUrl, vulnerabilityId } = req.body;
  
  const vuln = await Vulnerability.findByPk(vulnerabilityId);
  if (!vuln) {
    return res.status(404).json({ success: false, message: 'Vulnerability not found' });
  }
  
  const result = await sendWebhookNotification(webhookUrl, vuln.toJSON());
  
  res.json({
    success: result,
    message: result ? 'Webhook sent' : 'Failed to send webhook'
  });
}));

// ============================================================
// ASSET DISCOVERY
// ============================================================

router.post('/assets/discover', authenticateToken, [
  body('domain').isLength({ min: 1 }).withMessage('Domain required')
], validateRequest, asyncHandler(async (req, res) => {
  const { domain } = req.body;
  
  const assets = await discoverAssets(domain, req.user.id);
  
  res.json({
    success: true,
    data: {
      total: assets.length,
      assets
    }
  });
}));

router.get('/assets', authenticateToken, asyncHandler(async (req, res) => {
  const assets = await Asset.findAll({
    where: { userId: req.user.id },
    order: [['createdAt', 'DESC']]
  });
  
  res.json({
    success: true,
    data: { assets }
  });
}));

// ============================================================
// JWT SCAN
// ============================================================

router.post('/jwt', authenticateToken, [
  body('url').isLength({ min: 1 }).withMessage('URL required')
], validateRequest, asyncHandler(async (req, res) => {
  const { url } = req.body;
  
  const scan = await Scan.create({
    userId: req.user.id,
    name: 'JWT Scan: ' + url,
    target: url,
    type: 'web',
    status: 'running'
  });
  
  testJWTSecurity(url, scan.id)
    .then(async () => {
      await scan.update({ status: 'completed', progress: 100, endTime: new Date() });
    })
    .catch(async (e) => {
      await scan.update({ status: 'failed', errorMessage: e.message });
    });
  
  res.status(201).json({
    success: true,
    message: 'JWT scan started',
    data: { scan }
  });
}));

// ============================================================
// DNS SECURITY SCAN
// ============================================================

router.post('/dns', authenticateToken, [
  body('domain').isLength({ min: 1 }).withMessage('Domain required')
], validateRequest, asyncHandler(async (req, res) => {
  const { domain } = req.body;
  
  const scan = await Scan.create({
    userId: req.user.id,
    name: 'DNS Scan: ' + domain,
    target: domain,
    type: 'web',
    status: 'running'
  });
  
  testDNSSecurity(domain, scan.id)
    .then(async () => {
      await scan.update({ status: 'completed', progress: 100, endTime: new Date() });
    })
    .catch(async (e) => {
      await scan.update({ status: 'failed', errorMessage: e.message });
    });
  
  res.status(201).json({
    success: true,
    message: 'DNS security scan started',
    data: { scan }
  });
}));

// ============================================================
// SSL DEEP SCAN
// ============================================================

router.post('/ssl-deep', authenticateToken, [
  body('hostname').isLength({ min: 1 }).withMessage('Hostname required')
], validateRequest, asyncHandler(async (req, res) => {
  const { hostname } = req.body;
  
  const scan = await Scan.create({
    userId: req.user.id,
    name: 'SSL Deep Scan: ' + hostname,
    target: hostname,
    type: 'web',
    status: 'running'
  });
  
  testSSLDeep(hostname, scan.id)
    .then(async () => {
      await scan.update({ status: 'completed', progress: 100, endTime: new Date() });
    })
    .catch(async (e) => {
      await scan.update({ status: 'failed', errorMessage: e.message });
    });
  
  res.status(201).json({
    success: true,
    message: 'SSL deep scan started',
    data: { scan }
  });
}));

// ============================================================
// WAF DETECTION
// ============================================================

router.post('/waf', authenticateToken, [
  body('url').isLength({ min: 1 }).withMessage('URL required')
], validateRequest, asyncHandler(async (req, res) => {
  const { url } = req.body;
  
  const scan = await Scan.create({
    userId: req.user.id,
    name: 'WAF Detection: ' + url,
    target: url,
    type: 'web',
    status: 'running'
  });
  
  detectWAF(url, scan.id)
    .then(async () => {
      await scan.update({ status: 'completed', progress: 100, endTime: new Date() });
    })
    .catch(async (e) => {
      await scan.update({ status: 'failed', errorMessage: e.message });
    });
  
  res.status(201).json({
    success: true,
    message: 'WAF detection started',
    data: { scan }
  });
}));

module.exports = router;
