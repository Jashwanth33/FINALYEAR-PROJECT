const express = require('express');
const { body } = require('express-validator');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { validateRequest, asyncHandler } = require('../middleware/errorHandler');
const { Scan, Vulnerability } = require('../models');
const {
  mapAttackSurface,
  scanSupplyChain,
  pentestWorkflow,
  getThreatIntelligence,
  mlVulnerabilityDetection
} = require('../services/advancedProfessional');

const router = express.Router();

// ============================================================
// ATTACK SURFACE MAPPING
// ============================================================

router.post('/attack-surface', authenticateToken, [
  body('domain').isLength({ min: 1 }).withMessage('Domain required')
], validateRequest, asyncHandler(async (req, res) => {
  const { domain } = req.body;
  
  const result = await mapAttackSurface(domain, req.user.id);
  
  res.json({
    success: true,
    data: result
  });
}));

// ============================================================
// SUPPLY CHAIN SECURITY
// ============================================================

router.post('/supply-chain', authenticateToken, [
  body('repoUrl').isLength({ min: 1 }).withMessage('Repository URL required')
], validateRequest, asyncHandler(async (req, res) => {
  const { repoUrl } = req.body;
  
  const scan = await Scan.create({
    userId: req.user.id,
    name: 'Supply Chain Scan: ' + repoUrl,
    target: repoUrl,
    type: 'web',
    status: 'running'
  });
  
  scanSupplyChain(repoUrl, scan.id)
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
    message: 'Supply chain scan started',
    data: { scan }
  });
}));

// ============================================================
// PENETRATION TESTING WORKFLOW
// ============================================================

router.post('/pentest', authenticateToken, requireRole(['admin', 'analyst']), [
  body('target').isLength({ min: 1 }).withMessage('Target required')
], validateRequest, asyncHandler(async (req, res) => {
  const { target } = req.body;
  
  const scan = await Scan.create({
    userId: req.user.id,
    name: 'Penetration Test: ' + target,
    target,
    type: 'web',
    status: 'running'
  });
  
  const workflow = await pentestWorkflow(target, req.user.id);
  
  // Create vulnerabilities from workflow findings
  for (const phase of workflow.phases) {
    for (const finding of phase.findings) {
      await Vulnerability.create({
        scanId: scan.id,
        title: phase.name + ': ' + finding,
        description: finding,
        severity: 'medium',
        cvssScore: '5.3',
        url: target,
        evidence: finding,
        solution: 'Review and remediate',
        poc: 'Phase: ' + phase.name,
        pocType: 'markdown',
        status: 'open',
        category: 'pentest',
        confirmed: true
      });
    }
  }
  
  const vulns = await Vulnerability.findAll({ where: { scanId: scan.id } });
  
  await scan.update({
    status: 'completed',
    progress: 100,
    endTime: new Date(),
    summary: { total: vulns.length }
  });
  
  res.status(201).json({
    success: true,
    message: 'Penetration test completed',
    data: {
      scan,
      workflow,
      mitreAttack: workflow.mitreAttack,
      killChain: workflow.killChain
    }
  });
}));

// ============================================================
// THREAT INTELLIGENCE
// ============================================================

router.post('/threat-intel', authenticateToken, [
  body('domain').isLength({ min: 1 }).withMessage('Domain required')
], validateRequest, asyncHandler(async (req, res) => {
  const { domain } = req.body;
  
  const intel = await getThreatIntelligence(domain);
  
  res.json({
    success: true,
    data: intel
  });
}));

// ============================================================
// ML VULNERABILITY DETECTION
// ============================================================

router.post('/ml-detect', authenticateToken, [
  body('url').isLength({ min: 1 }).withMessage('URL required')
], validateRequest, asyncHandler(async (req, res) => {
  const { url } = req.body;
  
  const scan = await Scan.create({
    userId: req.user.id,
    name: 'ML Detection: ' + url,
    target: url,
    type: 'web',
    status: 'running'
  });
  
  mlVulnerabilityDetection(url, scan.id)
    .then(async () => {
      const vulns = await Vulnerability.findAll({ where: { scanId: scan.id } });
      await scan.update({
        status: 'completed',
        progress: 100,
        endTime: new Date(),
        summary: { total: vulns.length }
      });
    })
    .catch(async (e) => {
      await scan.update({ status: 'failed', errorMessage: e.message });
    });
  
  res.status(201).json({
    success: true,
    message: 'ML detection started',
    data: { scan }
  });
}));

module.exports = router;
