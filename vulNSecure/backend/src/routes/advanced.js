const express = require('express');
const { body, param, query } = require('express-validator');
const { Scan, Vulnerability, Asset, User } = require('../models');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { validateRequest, asyncHandler } = require('../middleware/errorHandler');
const { logger } = require('../utils/logger');
const {
  compareScans,
  trackRemediation,
  getRemediationMetrics,
  checkThreatIntelligence,
  analyzeAttackSurface,
  markFalsePositive,
  deduplicateVulnerabilities,
  generateAuditReport
} = require('../services/advancedFeatures');

const router = express.Router();

router.post('/compare', authenticateToken, [
  body('scanId1').isUUID().withMessage('Invalid scan ID 1'),
  body('scanId2').isUUID().withMessage('Invalid scan ID 2')
], validateRequest, asyncHandler(async (req, res) => {
  const { scanId1, scanId2 } = req.body;
  const comparison = await compareScans(scanId1, scanId2);
  res.json({ success: true, data: comparison });
}));

router.post('/vulnerabilities/:id/remediate', authenticateToken, [
  body('status').isIn(['in_progress', 'resolved', 'open']).withMessage('Invalid status'),
  body('notes').optional().isString()
], validateRequest, asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { status, notes } = req.body;
  const result = await trackRemediation(id, status, notes);
  res.json({ success: true, data: result });
}));

router.get('/metrics/remediation', authenticateToken, [
  query('days').optional().isInt({ min: 1, max: 365 }).withMessage('Days must be between 1 and 365')
], validateRequest, asyncHandler(async (req, res) => {
  const days = parseInt(req.query.days) || 30;
  const metrics = await getRemediationMetrics(req.user.id, days);
  res.json({ success: true, data: metrics });
}));

router.get('/threat-intel/:target', authenticateToken, asyncHandler(async (req, res) => {
  const { target } = req.params;
  const result = await checkThreatIntelligence(target);
  res.json({ success: true, data: result });
}));

router.get('/attack-surface/:target', authenticateToken, asyncHandler(async (req, res) => {
  const { target } = req.params;
  const analysis = await analyzeAttackSurface(target);
  res.json({ success: true, data: analysis });
}));

router.post('/vulnerabilities/:id/false-positive', authenticateToken, [
  body('reason').notEmpty().withMessage('Reason is required')
], validateRequest, asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { reason } = req.body;
  const result = await markFalsePositive(id, reason);
  res.json({ success: true, data: result });
}));

router.post('/scans/:id/deduplicate', authenticateToken, requireRole(['admin', 'analyst']), asyncHandler(async (req, res) => {
  const { id } = req.params;
  const result = await deduplicateVulnerabilities(id);
  res.json({ success: true, data: result });
}));

router.get('/audit/report', authenticateToken, [
  query('startDate').isISO8601().withMessage('Invalid start date'),
  query('endDate').isISO8601().withMessage('Invalid end date')
], validateRequest, asyncHandler(async (req, res) => {
  const { startDate, endDate } = req.query;
  const report = await generateAuditReport(req.user.id, new Date(startDate), new Date(endDate));
  res.json({ success: true, data: report });
}));

router.get('/compliance/:scanId', authenticateToken, [
  param('scanId').isUUID().withMessage('Invalid scan ID'),
  query('standard').optional().isIn(['owasp', 'pci-dss', 'hipaa', 'nist', 'soc2', 'all']).withMessage('Invalid standard')
], validateRequest, asyncHandler(async (req, res) => {
  const { scanId } = req.params;
  const { standard = 'all' } = req.query;

  const scan = await Scan.findByPk(scanId, {
    include: [{ model: Vulnerability, as: 'vulnerabilities' }]
  });

  if (!scan) {
    return res.status(404).json({ success: false, message: 'Scan not found' });
  }

  const vulnerabilities = scan.vulnerabilities || [];

  const complianceMappings = {
    'A01:2021': ['sql-injection', 'xss', 'command-injection', 'ssti'],
    'A02:2021': ['jwt', 'sensitive-data', 'crypto'],
    'A03:2021': ['sql-injection', 'xss', 'command-injection', 'ssti', 'xxe'],
    'A04:2021': ['idor', 'path-traversal', 'access-control'],
    'A05:2021': ['security-misconfiguration', 'cors', 'security-headers'],
    'A06:2021': ['vulnerable-component', 'outdated-software'],
    'A07:2021': ['authentication', 'brute-force'],
    'A08:2021': ['ssrf', 'xxe'],
    'A09:2021': ['logging', 'monitoring'],
    'A10:2021': ['ssrf']
  };

  const nistControls = {
    'AC': ['access-control', 'authentication', 'idor'],
    'AU': ['logging', 'monitoring'],
    'CA': ['security-misconfiguration'],
    'IA': ['authentication', 'brute-force'],
    'IR': ['ssrf', 'security-misconfiguration'],
    'MP': ['sensitive-data', 'crypto'],
    'PE': ['physical-security'],
    'PL': ['access-control'],
    'PS': ['authentication'],
    'RA': ['vulnerability-scanning'],
    'SA': ['sdlc'],
    'SC': ['ssl-tls', 'crypto', 'security-headers'],
    'SI': ['xss', 'sql-injection', 'command-injection']
  };

  const soc2Controls = {
    'CC6': ['access-control', 'encryption', 'authentication'],
    'CC7': ['vulnerability-scanning', 'patch-management'],
    'CC8': ['incident-response', 'monitoring']
  };

  const results = [];

  const standards = standard === 'all' ? ['owasp', 'pci-dss', 'hipaa', 'nist', 'soc2'] : [standard];

  for (const std of standards) {
    let checks = [];
    
    if (std === 'owasp') {
      for (const [owaspCode, categories] of Object.entries(complianceMappings)) {
        const vulns = vulnerabilities.filter(v => categories.includes(v.category));
        checks.push({
          standard: 'OWASP Top 10 2021',
          control: owaspCode,
          description: getOWASPDescription(owaspCode),
          status: vulns.length > 0 ? 'FAIL' : 'PASS',
          findings: vulns.length,
          vulnerabilities: vulns.map(v => ({ title: v.title, severity: v.severity }))
        });
      }
    }

    if (std === 'nist') {
      for (const [control, categories] of Object.entries(nistControls)) {
        const vulns = vulnerabilities.filter(v => categories.includes(v.category));
        checks.push({
          standard: 'NIST 800-53',
          control,
          description: `NIST Control ${control}`,
          status: vulns.length > 0 ? 'FAIL' : 'PASS',
          findings: vulns.length
        });
      }
    }

    if (std === 'soc2') {
      for (const [control, categories] of Object.entries(soc2Controls)) {
        const vulns = vulnerabilities.filter(v => categories.includes(v.category));
        checks.push({
          standard: 'SOC 2',
          control: `CC${control}`,
          description: `SOC 2 Trust Service Criteria ${control}`,
          status: vulns.length > 0 ? 'FAIL' : 'PASS',
          findings: vulns.length
        });
      }
    }

    if (std === 'pci-dss') {
      const pciCategories = ['sql-injection', 'xss', 'sensitive-data', 'crypto', 'authentication'];
      const pciVulns = vulnerabilities.filter(v => pciCategories.includes(v.category));
      checks.push({
        standard: 'PCI-DSS 4.0',
        control: 'Req 6.5.10',
        description: 'Injection flaws',
        status: pciVulns.length > 0 ? 'FAIL' : 'PASS',
        findings: pciVulns.length
      });
    }

    if (std === 'hipaa') {
      const hipaaCategories = ['sql-injection', 'xss', 'sensitive-data', 'security-misconfiguration'];
      const hipaaVulns = vulnerabilities.filter(v => hipaaCategories.includes(v.category));
      checks.push({
        standard: 'HIPAA',
        control: '164.312(a)',
        description: 'Access Control',
        status: hipaaVulns.length > 0 ? 'FAIL' : 'PASS',
        findings: hipaaVulns.length
      });
    }

    results.push({ standard: std.toUpperCase(), checks });
  }

  res.json({ success: true, data: results });
}));

const getOWASPDescription = (code) => {
  const descriptions = {
    'A01:2021': 'Broken Access Control',
    'A02:2021': 'Cryptographic Failures',
    'A03:2021': 'Injection',
    'A04:2021': 'Insecure Design',
    'A05:2021': 'Security Misconfiguration',
    'A06:2021': 'Vulnerable and Outdated Components',
    'A07:2021': 'Identification and Authentication Failures',
    'A08:2021': 'Software and Data Integrity Failures',
    'A09:2021': 'Security Logging and Monitoring Failures',
    'A10:2021': 'Server-Side Request Forgery'
  };
  return descriptions[code] || code;
};

module.exports = router;
