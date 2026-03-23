const express = require('express');
const { Op } = require('sequelize');
const { Scan, Vulnerability, Leak, CVE, User, AuditLog } = require('../models');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');

const router = express.Router();

// @route   GET /api/analytics/overview
// @desc    Get advanced analytics overview
// @access  Private
router.get('/overview', authenticateToken, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;
  const scanWhere = userRole === 'admin' ? {} : { userId };

  // Get trends for last 30 days
  const thirtyDaysAgo = new Date();
  thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

  // Vulnerability trends
  const vulnTrends = await getVulnerabilityTrends(scanWhere, thirtyDaysAgo);
  
  // Scan trends
  const scanTrends = await getScanTrends(scanWhere, thirtyDaysAgo);
  
  // Risk score calculation
  const riskScore = await calculateRiskScore(scanWhere);
  
  // Top vulnerabilities
  const topVulns = await getTopVulnerabilities(scanWhere);
  
  // Asset inventory
  const assets = await getAssetInventory(scanWhere);
  
  // Remediation metrics
  const remediation = await getRemediationMetrics(scanWhere);

  res.json({
    success: true,
    data: {
      riskScore,
      vulnTrends,
      scanTrends,
      topVulns,
      assets,
      remediation,
      summary: {
        totalScans: await Scan.count({ where: scanWhere }),
        totalVulns: await Vulnerability.count({ include: [{ model: Scan, where: scanWhere, attributes: [] }] }),
        resolvedVulns: await Vulnerability.count({ 
          where: { status: 'resolved' },
          include: [{ model: Scan, where: scanWhere, attributes: [] }]
        }),
        avgResolutionTime: remediation.avgResolutionTime
      }
    }
  });
}));

// @route   GET /api/analytics/trends
// @desc    Get vulnerability trends over time
// @access  Private
router.get('/trends', authenticateToken, asyncHandler(async (req, res) => {
  const { days = 30 } = req.query;
  const userId = req.user.id;
  const userRole = req.user.role;
  const scanWhere = userRole === 'admin' ? {} : { userId };

  const startDate = new Date();
  startDate.setDate(startDate.getDate() - parseInt(days));

  const trends = await Vulnerability.findAll({
    attributes: [
      [require('sequelize').fn('DATE', require('sequelize').col('created_at')), 'date'],
      [require('sequelize').fn('COUNT', require('sequelize').col('id')), 'count'],
      'severity'
    ],
    include: [{
      model: Scan,
      where: scanWhere,
      attributes: []
    }],
    where: {
      createdAt: { [Op.gte]: startDate }
    },
    group: ['date', 'severity'],
    order: [[require('sequelize').fn('DATE', require('sequelize').col('created_at')), 'ASC']]
  });

  res.json({ success: true, data: { trends } });
}));

// @route   GET /api/analytics/riskscore
// @desc    Calculate risk score for organization
// @access  Private
router.get('/riskscore', authenticateToken, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;
  const scanWhere = userRole === 'admin' ? {} : { userId };

  const riskScore = await calculateRiskScore(scanWhere);
  const riskFactors = await getRiskFactors(scanWhere);

  res.json({
    success: true,
    data: {
      score: riskScore,
      grade: getGrade(riskScore),
      factors: riskFactors,
      recommendations: getRecommendations(riskScore, riskFactors)
    }
  });
}));

// @route   GET /api/analytics/assets
// @desc    Get asset inventory
// @access  Private
router.get('/assets', authenticateToken, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;
  const scanWhere = userRole === 'admin' ? {} : { userId };

  const assets = await Scan.findAll({
    where: { ...scanWhere, status: 'completed' },
    attributes: [
      'target',
      'type',
      [require('sequelize').fn('COUNT', require('sequelize').col('Scan.id')), 'scanCount'],
      [require('sequelize').fn('MAX', require('sequelize').col('created_at')), 'lastScanned']
    ],
    group: ['target', 'type'],
    order: [[require('sequelize').fn('MAX', require('sequelize').col('created_at')), 'DESC']]
  });

  // Get vulnerability count per asset
  const assetData = await Promise.all(assets.map(async (asset) => {
    const target = asset.target;
    const scans = await Scan.findAll({ 
      where: { ...scanWhere, target, status: 'completed' },
      attributes: ['id']
    });
    const scanIds = scans.map(s => s.id);
    
    const vulnCount = await Vulnerability.count({
      where: { scanId: { [Op.in]: scanIds } }
    });

    return {
      target: asset.target,
      type: asset.type,
      scanCount: asset.dataValues.scanCount,
      lastScanned: asset.dataValues.lastScanned,
      vulnCount
    };
  }));

  res.json({ success: true, data: { assets: assetData } });
}));

// @route   GET /api/analytics/remediation
// @desc    Get remediation tracking
// @access  Private
router.get('/remediation', authenticateToken, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;
  const scanWhere = userRole === 'admin' ? {} : { userId };

  const remediation = await getRemediationMetrics(scanWhere);

  // Get recent remediations
  const recentRemediated = await Vulnerability.findAll({
    where: { status: 'resolved' },
    include: [{
      model: Scan,
      where: scanWhere,
      attributes: ['target']
    }],
    order: [['updatedAt', 'DESC']],
    limit: 10
  });

  res.json({
    success: true,
    data: {
      ...remediation,
      recentRemediated
    }
  });
}));

// Helper functions
const getVulnerabilityTrends = async (scanWhere, startDate) => {
  const vulns = await Vulnerability.findAll({
    attributes: [
      [require('sequelize').fn('DATE', require('sequelize').col('created_at')), 'date'],
      [require('sequelize').fn('COUNT', require('sequelize').col('id')), 'count']
    ],
    include: [{ model: Scan, where: scanWhere, attributes: [] }],
    where: { createdAt: { [Op.gte]: startDate } },
    group: ['date'],
    order: [[require('sequelize').fn('DATE', require('sequelize').col('created_at')), 'ASC']],
    raw: false
  });
  return vulns;
};

const getScanTrends = async (scanWhere, startDate) => {
  const scans = await Scan.findAll({
    attributes: [
      [require('sequelize').fn('DATE', require('sequelize').col('created_at')), 'date'],
      [require('sequelize').fn('COUNT', require('sequelize').col('id')), 'count']
    ],
    where: { ...scanWhere, createdAt: { [Op.gte]: startDate } },
    group: ['date'],
    order: [[require('sequelize').fn('DATE', require('sequelize').col('created_at')), 'ASC']]
  });
  return scans;
};

const calculateRiskScore = async (scanWhere) => {
  const severityWeights = { critical: 10, high: 7, medium: 4, low: 1 };
  
  const vulns = await Vulnerability.findAll({
    include: [{ model: Scan, where: scanWhere, attributes: [] }],
    attributes: ['severity']
  });

  let riskScore = 100;
  vulns.forEach(v => {
    riskScore -= severityWeights[v.severity] || 0;
  });

  return Math.max(0, Math.min(100, riskScore));
};

const getRiskFactors = async (scanWhere) => {
  const factors = [];
  
  const critical = await Vulnerability.count({
    include: [{ model: Scan, where: scanWhere, attributes: [] }],
    where: { severity: 'critical', status: 'open' }
  });
  
  const high = await Vulnerability.count({
    include: [{ model: Scan, where: scanWhere, attributes: [] }],
    where: { severity: 'high', status: 'open' }
  });

  const unpatched = await Vulnerability.count({
    include: [{ model: Scan, where: scanWhere, attributes: [] }],
    where: { 
      status: 'open',
      createdAt: { [Op.lt]: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
    }
  });

  if (critical > 0) factors.push({ factor: 'Critical vulnerabilities present', weight: 30, severity: 'critical' });
  if (high > 5) factors.push({ factor: 'Multiple high severity vulnerabilities', weight: 20, severity: 'high' });
  if (unpatched > 10) factors.push({ factor: 'Old unresolved vulnerabilities', weight: 15, severity: 'medium' });

  return factors;
};

const getGrade = (score) => {
  if (score >= 90) return 'A+';
  if (score >= 80) return 'A';
  if (score >= 70) return 'B';
  if (score >= 60) return 'C';
  if (score >= 50) return 'D';
  return 'F';
};

const getRecommendations = (score, factors) => {
  const recommendations = [];
  
  if (score < 50) {
    recommendations.push('Immediate action required - critical vulnerabilities detected');
    recommendations.push('Consider engaging a security team for emergency response');
  }
  
  const criticalFactors = factors.filter(f => f.severity === 'critical');
  if (criticalFactors.length > 0) {
    recommendations.push('Prioritize remediation of critical vulnerabilities within 24 hours');
  }
  
  recommendations.push('Implement regular vulnerability scanning schedule');
  recommendations.push('Establish patch management process');
  recommendations.push('Consider security awareness training');
  
  return recommendations;
};

const getTopVulnerabilities = async (scanWhere) => {
  const vulns = await Vulnerability.findAll({
    include: [{
      model: Scan,
      where: scanWhere,
      attributes: ['target']
    }],
    attributes: ['title', 'severity', 'status', 'createdAt'],
    where: { status: 'open' },
    order: [
      ['severity', 'DESC'],
      ['createdAt', 'DESC']
    ],
    limit: 10
  });
  return vulns;
};

const getAssetInventory = async (scanWhere) => {
  const assets = await Scan.findAll({
    where: { ...scanWhere, status: 'completed' },
    attributes: ['target', 'type', 'id'],
    order: [['createdAt', 'DESC']],
    limit: 50
  });
  return assets;
};

const getRemediationMetrics = async (scanWhere) => {
  const total = await Vulnerability.count({
    include: [{ model: Scan, where: scanWhere, attributes: [] }]
  });
  
  const resolved = await Vulnerability.count({
    include: [{ model: Scan, where: scanWhere, attributes: [] }],
    where: { status: 'resolved' }
  });
  
  const open = await Vulnerability.count({
    include: [{ model: Scan, where: scanWhere, attributes: [] }],
    where: { status: 'open' }
  });

  // Calculate average resolution time (mock for now)
  const avgResolutionTime = 7; // days

  return {
    total,
    resolved,
    open,
    resolvedPercentage: total > 0 ? Math.round((resolved / total) * 100) : 0,
    avgResolutionTime
  };
};

// @route   POST /api/analytics/audit
// @desc    Log user action for audit
// @access  Private
router.post('/audit', authenticateToken, asyncHandler(async (req, res) => {
  const { action, resource, details } = req.body;
  const userId = req.user.id;

  await AuditLog.create({
    userId,
    action,
    resource,
    details,
    ipAddress: req.ip
  });

  res.json({ success: true });
}));

module.exports = router;
