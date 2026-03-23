const express = require('express');
const { body, param, query } = require('express-validator');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { validateRequest, asyncHandler } = require('../middleware/errorHandler');
const {
  analyzeVulnerabilityAI,
  analyzeBlockchain,
  scanIoTDevice,
  analyzeAPIGateway,
  analyzeSupplyChain,
  analyzeMobileApp,
  assessSocialEngineering,
  modelAttackPath,
  generateSecurityMetrics,
  analyzeDevSecOps
} = require('../services/nextGenFeatures');
const { Vulnerability, Scan } = require('../models');

const router = express.Router();

router.get('/ai/analyze-vulnerability/:id', authenticateToken, asyncHandler(async (req, res) => {
  const { id } = req.params;
  const vulnerability = await Vulnerability.findByPk(id);
  
  if (!vulnerability) {
    return res.status(404).json({ success: false, message: 'Vulnerability not found' });
  }
  
  const analysis = await analyzeVulnerabilityAI(vulnerability);
  res.json({ success: true, data: analysis });
}));

router.get('/blockchain/security', authenticateToken, [
  query('target').notEmpty().withMessage('Target required')
], validateRequest, asyncHandler(async (req, res) => {
  const { target } = req.query;
  const results = await analyzeBlockchain(target);
  res.json({ success: true, data: results });
}));

router.get('/iot/scan', authenticateToken, [
  query('target').notEmpty().withMessage('Target required')
], validateRequest, asyncHandler(async (req, res) => {
  const { target } = req.query;
  const results = await scanIoTDevice(target);
  res.json({ success: true, data: results });
}));

router.get('/api-gateway/security', authenticateToken, [
  query('gateway').notEmpty().withMessage('Gateway URL required')
], validateRequest, asyncHandler(async (req, res) => {
  const { gateway } = req.query;
  const results = await analyzeAPIGateway(gateway);
  res.json({ success: true, data: results });
}));

router.get('/supply-chain', authenticateToken, [
  query('target').notEmpty().withMessage('Target required')
], validateRequest, asyncHandler(async (req, res) => {
  const { target } = req.query;
  const results = await analyzeSupplyChain(target);
  res.json({ success: true, data: results });
}));

router.get('/mobile/security', authenticateToken, [
  query('package').notEmpty().withMessage('Package required')
], validateRequest, asyncHandler(async (req, res) => {
  const { package } = req.query;
  const results = await analyzeMobileApp(package);
  res.json({ success: true, data: results });
}));

router.get('/social-engineering', authenticateToken, [
  query('target').notEmpty().withMessage('Target required')
], validateRequest, asyncHandler(async (req, res) => {
  const { target } = req.query;
  const results = await assessSocialEngineering(target);
  res.json({ success: true, data: results });
}));

router.get('/attack-path', authenticateToken, [
  query('target').notEmpty().withMessage('Target required')
], validateRequest, asyncHandler(async (req, res) => {
  const { target } = req.query;
  const results = await modelAttackPath(target);
  res.json({ success: true, data: results });
}));

router.get('/metrics/security', authenticateToken, asyncHandler(async (req, res) => {
  const scans = await Scan.findAll({ limit: 30 });
  const vulnerabilities = await Vulnerability.findAll();
  const metrics = await generateSecurityMetrics(scans, vulnerabilities);
  res.json({ success: true, data: metrics });
}));

router.get('/devsecops', authenticateToken, [
  query('pipeline').optional().isString()
], validateRequest, asyncHandler(async (req, res) => {
  const results = await analyzeDevSecOps(req.query.pipeline || {});
  res.json({ success: true, data: results });
}));

module.exports = router;
