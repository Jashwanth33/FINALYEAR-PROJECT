const { Scan, Vulnerability, Asset, AuditLog } = require('../models');
const { Op } = require('sequelize');

const compareScans = async (scanId1, scanId2) => {
  const scan1 = await Scan.findByPk(scanId1, {
    include: [{ model: Vulnerability, as: 'vulnerabilities' }]
  });
  const scan2 = await Scan.findByPk(scanId2, {
    include: [{ model: Vulnerability, as: 'vulnerabilities' }]
  });

  if (!scan1 || !scan2) {
    throw new Error('One or both scans not found');
  }

  const vulns1 = scan1.vulnerabilities || [];
  const vulns2 = scan2.vulnerabilities || [];

  const vulns1Urls = new Set(vulns1.map(v => v.url + v.title));
  const vulns2Urls = new Set(vulns2.map(v => v.url + v.title));

  const newVulns = vulns2.filter(v => !vulns1Urls.has(v.url + v.title));
  const fixedVulns = vulns1.filter(v => !vulns2Urls.has(v.url + v.title));
  const persistentVulns = vulns2.filter(v => vulns1Urls.has(v.url + v.title));

  const severityChanges = {};
  for (const v2 of vulns2) {
    const v1 = vulns1.find(v => v.url === v2.url && v.title === v2.title);
    if (v1 && v1.severity !== v2.severity) {
      severityChanges[v2.id] = { from: v1.severity, to: v2.severity };
    }
  }

  const riskScore1 = calculateRiskScore(vulns1);
  const riskScore2 = calculateRiskScore(vulns2);

  return {
    scan1: { id: scan1.id, name: scan1.name, target: scan1.target, date: scan1.createdAt, riskScore: riskScore1, totalVulns: vulns1.length },
    scan2: { id: scan2.id, name: scan2.name, target: scan2.target, date: scan2.createdAt, riskScore: riskScore2, totalVulns: vulns2.length },
    comparison: {
      newVulnerabilities: newVulns.length,
      fixedVulnerabilities: fixedVulns.length,
      persistentVulnerabilities: persistentVulns.length,
      severityChanges,
      riskScoreChange: riskScore2 - riskScore1
    },
    details: {
      new: newVulns.map(v => ({ title: v.title, severity: v.severity, url: v.url })),
      fixed: fixedVulns.map(v => ({ title: v.title, severity: v.severity, url: v.url })),
      persistent: persistentVulns.map(v => ({ title: v.title, severity: v.severity, url: v.url }))
    }
  };
};

const calculateRiskScore = (vulnerabilities) => {
  if (!vulnerabilities.length) return 100;
  const weights = { critical: 10, high: 7, medium: 4, low: 1 };
  let score = 100;
  for (const vuln of vulnerabilities) {
    score -= weights[vuln.severity] || 1;
  }
  return Math.max(0, Math.min(100, score));
};

const trackRemediation = async (vulnerabilityId, status, notes) => {
  const vulnerability = await Vulnerability.findByPk(vulnerabilityId);
  if (!vulnerability) throw new Error('Vulnerability not found');

  const oldStatus = vulnerability.status;
  await vulnerability.update({ status });

  await AuditLog.create({
    userId: vulnerability.scan?.userId,
    action: 'remediation_update',
    resource: 'vulnerability',
    resourceId: vulnerability.id,
    details: { oldStatus, newStatus: status, notes },
    ipAddress: '0.0.0.0'
  });

  return { vulnerability, previousStatus: oldStatus, newStatus: status };
};

const getRemediationMetrics = async (userId, dateRange = 30) => {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - dateRange);

  const vulnerabilities = await Vulnerability.findAll({
    where: {
      createdAt: { [Op.gte]: startDate }
    }
  });

  const total = vulnerabilities.length;
  const open = vulnerabilities.filter(v => v.status === 'open').length;
  const inProgress = vulnerabilities.filter(v => v.status === 'in_progress').length;
  const remediated = vulnerabilities.filter(v => v.status === 'resolved').length;
  const falsePositive = vulnerabilities.filter(v => v.status === 'false_positive').length;

  const avgRemediationTime = await calculateAvgRemediationTime(vulnerabilities);

  const bySeverity = {
    critical: { open: 0, inProgress: 0, resolved: 0 },
    high: { open: 0, inProgress: 0, resolved: 0 },
    medium: { open: 0, inProgress: 0, resolved: 0 },
    low: { open: 0, inProgress: 0, resolved: 0 }
  };

  for (const vuln of vulnerabilities) {
    if (bySeverity[vuln.severity]) {
      bySeverity[vuln.severity][vuln.status === 'resolved' ? 'resolved' : vuln.status === 'in_progress' ? 'inProgress' : 'open']++;
    }
  }

  return {
    summary: { total, open, inProgress, remediated, falsePositive, avgRemediationTime },
    bySeverity,
    trend: await getRemediationTrend(startDate)
  };
};

const calculateAvgRemediationTime = async (vulnerabilities) => {
  const resolved = vulnerabilities.filter(v => v.status === 'resolved' && v.updatedAt > v.createdAt);
  if (!resolved.length) return 0;
  
  let totalTime = 0;
  for (const vuln of resolved) {
    totalTime += (new Date(vuln.updatedAt) - new Date(vuln.createdAt)) / (1000 * 60 * 60 * 24);
  }
  return Math.round(totalTime / resolved.length);
};

const getRemediationTrend = async (startDate) => {
  const vulns = await Vulnerability.findAll({
    where: { createdAt: { [Op.gte]: startDate }, status: 'resolved' },
    order: [['updatedAt', 'ASC']]
  });

  const trend = {};
  for (const vuln of vulns) {
    const date = new Date(vuln.updatedAt).toISOString().split('T')[0];
    trend[date] = (trend[date] || 0) + 1;
  }
  return trend;
};

const checkThreatIntelligence = async (target) => {
  const iocs = [];

  const knownMaliciousPatterns = [
    { pattern: 'suspicious-domain', risk: 'high' },
    { pattern: 'malware', risk: 'critical' },
    { pattern: 'phishing', risk: 'high' },
    { pattern: 'botnet', risk: 'critical' }
  ];

  const threatFeeds = await fetchThreatFeeds(target);
  iocs.push(...threatFeeds);

  const dnsRecords = await resolveDNS(target);
  for (const record of dnsRecords) {
    const matches = knownMaliciousPatterns.filter(p => record.includes(p.pattern));
    if (matches.length) {
      iocs.push({ type: 'dns', value: record, risk: matches[0].risk, source: 'local' });
    }
  }

  return { target, iocs: iocs.length > 0 ? iocs : null, checkedAt: new Date() };
};

const fetchThreatFeeds = async (target) => {
  return [];
};

const resolveDNS = async (domain) => {
  const dns = require('dns').promises;
  try {
    const a = await dns.resolve4(domain);
    const aaaa = await dns.resolve6(domain);
    return [...(a || []), ...(aaaa || [])];
  } catch {
    return [];
  }
};

const analyzeAttackSurface = async (target) => {
  const surface = {
    endpoints: [],
    technologies: [],
    entryPoints: [],
    dataExposure: [],
    attackVectors: []
  };

  const commonPaths = [
    '/admin', '/api', '/login', '/wp-admin', '/phpmyadmin',
    '/.git', '/.env', '/backup', '/config', '/debug',
    '/status', '/health', '/actuator', '/swagger', '/docs'
  ];

  const axios = require('axios');
  for (const path of commonPaths) {
    try {
      const url = target.replace(/\/$/, '') + path;
      const response = await axios.get(url, { timeout: 3000, validateStatus: () => true });
      if (response.status < 400) {
        surface.endpoints.push({ path, status: response.status, methods: ['GET'] });
        
        if (path.includes('admin')) surface.attackVectors.push('Administrative interface exposed');
        if (path.includes('api')) { surface.attackVectors.push('API endpoint exposed'); surface.entryPoints.push({ type: 'api', path }); }
        if (path.includes('.git')) { surface.dataExposure.push('Git repository exposed'); surface.attackVectors.push('Source code exposure'); }
        if (path.includes('.env')) { surface.dataExposure.push('Environment file exposed'); surface.attackVectors.push('Credential exposure'); }
      }
    } catch {}
  }

  const techPatterns = [
    { pattern: /WordPress/i, name: 'WordPress', risks: ['Vulnerable plugins', 'Default credentials'] },
    { pattern: /Drupal/i, name: 'Drupal', risks: ['Known CVEs', 'Module vulnerabilities'] },
    { pattern: /Express/i, name: 'Express.js', risks: ['Node.js vulnerabilities', 'Prototype pollution'] },
    { pattern: /Apache/i, name: 'Apache', risks: ['Known CVEs', 'Module vulnerabilities'] },
    { pattern: /Nginx/i, name: 'Nginx', risks: ['Configuration issues', 'Known CVEs'] }
  ];

  try {
    const response = await axios.get(target, { timeout: 5000 });
    const content = response.data.toString();
    
    for (const tech of techPatterns) {
      if (tech.pattern.test(content)) {
        surface.technologies.push(tech);
        surface.attackVectors.push(...tech.risks.map(r => `${tech.name}: ${r}`));
      }
    }

    if (response.headers['server']) {
      surface.technologies.push({ name: response.headers['server'], type: 'server' });
    }
  } catch {}

  surface.riskScore = calculateAttackSurfaceRisk(surface);
  surface.recommendations = generateRecommendations(surface);

  return surface;
};

const calculateAttackSurfaceRisk = (surface) => {
  let score = 100;
  score -= surface.endpoints.length * 2;
  score -= surface.dataExposure.length * 10;
  score -= surface.attackVectors.filter(v => v.includes('exposed')).length * 5;
  return Math.max(0, Math.min(100, score));
};

const generateRecommendations = (surface) => {
  const recommendations = [];
  
  if (surface.dataExposure.includes('Environment file exposed')) {
    recommendations.push({ priority: 'high', title: 'Secure .env files', description: 'Remove or restrict access to .env files' });
  }
  if (surface.dataExposure.includes('Git repository exposed')) {
    recommendations.push({ priority: 'high', title: 'Secure Git repository', description: 'Block .git directory access' });
  }
  if (surface.endpoints.some(e => e.path.includes('admin'))) {
    recommendations.push({ priority: 'medium', title: 'Secure admin interfaces', description: 'Implement strong authentication for admin areas' });
  }
  if (surface.attackVectors.includes('API endpoint exposed')) {
    recommendations.push({ priority: 'medium', title: 'Secure API endpoints', description: 'Implement rate limiting and authentication' });
  }

  return recommendations;
};

const markFalsePositive = async (vulnerabilityId, reason) => {
  const vulnerability = await Vulnerability.findByPk(vulnerabilityId);
  if (!vulnerability) throw new Error('Vulnerability not found');

  await vulnerability.update({ 
    status: 'false_positive',
    falsePositiveReason: reason
  });

  return vulnerability;
};

const deduplicateVulnerabilities = async (scanId) => {
  const vulns = await Vulnerability.findAll({ where: { scanId } });
  
  const seen = new Map();
  const duplicates = [];

  for (const vuln of vulns) {
    const key = `${vuln.url}-${vuln.title}`;
    if (seen.has(key)) {
      duplicates.push(vuln.id);
    } else {
      seen.set(key, vuln.id);
    }
  }

  if (duplicates.length > 0) {
    await Vulnerability.destroy({ where: { id: { [Op.in]: duplicates } } });
  }

  return { removed: duplicates.length, unique: vulns.length - duplicates.length };
};

const generateAuditReport = async (userId, startDate, endDate) => {
  const logs = await AuditLog.findAll({
    where: {
      userId,
      createdAt: { [Op.between]: [startDate, endDate] }
    },
    order: [['createdAt', 'DESC']]
  });

  const byAction = {};
  for (const log of logs) {
    byAction[log.action] = (byAction[log.action] || 0) + 1;
  }

  return {
    period: { start: startDate, end: endDate },
    totalActions: logs.length,
    byAction,
    logs: logs.slice(0, 100).map(l => ({
      action: l.action,
      resource: l.resource,
      details: l.details,
      timestamp: l.createdAt
    }))
  };
};

module.exports = {
  compareScans,
  trackRemediation,
  getRemediationMetrics,
  checkThreatIntelligence,
  analyzeAttackSurface,
  markFalsePositive,
  deduplicateVulnerabilities,
  generateAuditReport
};
