const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Scan, Vulnerability, User, AuditLog } = require('../models');
const { logger } = require('../utils/logger');

// ============================================================
// 1. EXPORT OPTIONS (CSV, JSON, Excel)
// ============================================================

const exportToCSV = async (scanId) => {
  const vulns = await Vulnerability.findAll({ where: { scanId } });
  
  let csv = 'Title,Severity,CVSS,URL,Category,Status,CVE,Description,Solution\n';
  
  for (const v of vulns) {
    csv += `"${v.title}","${v.severity}","${v.cvssScore || 'N/A'}","${v.url || 'N/A'}","${v.category}","${v.status}","${v.cveId || 'N/A'}","${(v.description || '').replace(/"/g, '""')}","${(v.solution || '').replace(/"/g, '""')}"\n`;
  }
  
  return csv;
};

const exportToJSON = async (scanId) => {
  const scan = await Scan.findByPk(scanId, {
    include: [{ model: Vulnerability, as: 'vulnerabilities' }]
  });
  
  return JSON.stringify({
    scan: {
      id: scan.id,
      name: scan.name,
      target: scan.target,
      status: scan.status,
      createdAt: scan.createdAt
    },
    vulnerabilities: scan.vulnerabilities.map(v => ({
      id: v.id,
      title: v.title,
      severity: v.severity,
      cvssScore: v.cvssScore,
      url: v.url,
      category: v.category,
      description: v.description,
      evidence: v.evidence,
      solution: v.solution,
      poc: v.poc,
      status: v.status
    }))
  }, null, 2);
};

const exportToExcel = async (scanId) => {
  // Generate CSV format for Excel compatibility
  return await exportToCSV(scanId);
};

// ============================================================
// 2. AUDIT LOG
// ============================================================

const logActivity = async (userId, action, details, ip = null) => {
  try {
    await AuditLog.create({
      userId,
      action,
      details: typeof details === 'string' ? details : JSON.stringify(details),
      ipAddress: ip,
      timestamp: new Date()
    });
  } catch (e) {
    logger.error('Failed to log activity: ' + e.message);
  }
};

const getAuditLogs = async (userId, limit = 50) => {
  return await AuditLog.findAll({
    where: userId ? { userId } : {},
    order: [['timestamp', 'DESC']],
    limit
  });
};

// ============================================================
// 3. SCAN COMPARISON
// ============================================================

const compareScans = async (scanId1, scanId2) => {
  const vulns1 = await Vulnerability.findAll({ where: { scanId: scanId1 } });
  const vulns2 = await Vulnerability.findAll({ where: { scanId: scanId2 } });
  
  const vulns1Keys = new Set(vulns1.map(v => v.url + v.title));
  const vulns2Keys = new Set(vulns2.map(v => v.url + v.title));
  
  const newVulns = vulns2.filter(v => !vulns1Keys.has(v.url + v.title));
  const fixedVulns = vulns1.filter(v => !vulns2Keys.has(v.url + v.title));
  const persistentVulns = vulns2.filter(v => vulns1Keys.has(v.url + v.title));
  
  return {
    comparison: {
      new: newVulns.length,
      fixed: fixedVulns.length,
      persistent: persistentVulns.length
    },
    details: {
      newVulns: newVulns.map(v => ({ title: v.title, severity: v.severity, url: v.url })),
      fixedVulns: fixedVulns.map(v => ({ title: v.title, severity: v.severity, url: v.url })),
      persistentVulns: persistentVulns.map(v => ({ title: v.title, severity: v.severity, url: v.url }))
    },
    trends: {
      improving: fixedVulns.length > newVulns.length,
      worsening: newVulns.length > fixedVulns.length,
      stable: newVulns.length === fixedVulns.length
    }
  };
};

// ============================================================
// 4. REMEDIATION TRACKING
// ============================================================

const updateRemediation = async (vulnerabilityId, data) => {
  const vuln = await Vulnerability.findByPk(vulnerabilityId);
  if (!vuln) throw new Error('Vulnerability not found');
  
  await vuln.update({
    status: data.status || vuln.status,
    assignedTo: data.assignedTo || vuln.assignedTo,
    dueDate: data.dueDate || vuln.dueDate,
    remediation: {
      ...vuln.remediation,
      assignedBy: data.assignedBy,
      assignedAt: new Date().toISOString(),
      notes: data.notes,
      fixVerified: data.fixVerified || false
    }
  });
  
  return vuln;
};

const getRemediationStats = async (userId) => {
  const openCount = await Vulnerability.count({ where: { status: 'open' } });
  const inProgressCount = await Vulnerability.count({ where: { status: 'in_progress' } });
  const fixedCount = await Vulnerability.count({ where: { status: 'fixed' } });
  const acceptedCount = await Vulnerability.count({ where: { status: 'accepted' } });
  
  return {
    open: openCount,
    inProgress: inProgressCount,
    fixed: fixedCount,
    accepted: acceptedCount,
    total: openCount + inProgressCount + fixedCount + acceptedCount
  };
};

// ============================================================
// 5. BULK SCANNING
// ============================================================

const startBulkScan = async (targets, userId) => {
  const results = [];
  
  for (const target of targets) {
    try {
      const scan = await Scan.create({
        userId,
        name: 'Bulk: ' + target,
        target,
        type: 'web',
        status: 'pending'
      });
      
      results.push({ target, scanId: scan.id, status: 'queued' });
    } catch (e) {
      results.push({ target, status: 'failed', error: e.message });
    }
  }
  
  return results;
};

// ============================================================
// 6. CUSTOM RULES
// ============================================================

const createCustomRule = async (userId, rule) => {
  const ruleData = {
    id: crypto.randomUUID(),
    userId,
    name: rule.name,
    description: rule.description,
    pattern: rule.pattern,
    severity: rule.severity,
    category: rule.category,
    enabled: true,
    createdAt: new Date()
  };
  
  // Store in file for simplicity
  const rulesFile = path.join(__dirname, '../../data/custom_rules.json');
  let rules = [];
  
  try {
    if (fs.existsSync(rulesFile)) {
      rules = JSON.parse(fs.readFileSync(rulesFile, 'utf8'));
    }
  } catch (e) {}
  
  rules.push(ruleData);
  fs.writeFileSync(rulesFile, JSON.stringify(rules, null, 2));
  
  return ruleData;
};

const getCustomRules = async (userId) => {
  const rulesFile = path.join(__dirname, '../../data/custom_rules.json');
  
  try {
    if (fs.existsSync(rulesFile)) {
      const rules = JSON.parse(fs.readFileSync(rulesFile, 'utf8'));
      return rules.filter(r => r.userId === userId || !r.userId);
    }
  } catch (e) {}
  
  return [];
};

// ============================================================
// 7. PASSWORD RESET
// ============================================================

const generateResetToken = async (email) => {
  const user = await User.findOne({ where: { email } });
  if (!user) throw new Error('User not found');
  
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + 3600000); // 1 hour
  
  await user.update({
    passwordResetToken: token,
    passwordResetExpires: expires
  });
  
  return { token, expires };
};

const resetPassword = async (token, newPassword) => {
  const user = await User.findOne({
    where: {
      passwordResetToken: token,
      passwordResetExpires: { $gt: new Date() }
    }
  });
  
  if (!user) throw new Error('Invalid or expired token');
  
  const bcrypt = require('bcryptjs');
  const hashedPassword = await bcrypt.hash(newPassword, 10);
  
  await user.update({
    password: hashedPassword,
    passwordResetToken: null,
    passwordResetExpires: null
  });
  
  return user;
};

// ============================================================
// 8. TWO-FACTOR AUTHENTICATION
// ============================================================

const generate2FASecret = async (userId) => {
  const secret = crypto.randomBytes(20).toString('hex');
  const backupCodes = Array.from({ length: 10 }, () => 
    crypto.randomBytes(4).toString('hex')
  );
  
  return {
    secret,
    backupCodes,
    qrCode: `otpauth://totp/vulNSecure?secret=${secret}&issuer=vulNSecure`
  };
};

const verify2FA = async (userId, token, secret) => {
  // Simple verification - in production use speakeasy or otpauth
  return token.length === 6 && /^\d+$/.test(token);
};

// ============================================================
// 9. RATE LIMITING CONFIG
// ============================================================

const rateLimitConfig = {
  api: { windowMs: 60000, max: 100 },
  scans: { windowMs: 3600000, max: 10 },
  login: { windowMs: 900000, max: 5 }
};

const updateRateLimit = (type, config) => {
  if (rateLimitConfig[type]) {
    rateLimitConfig[type] = { ...rateLimitConfig[type], ...config };
  }
  return rateLimitConfig;
};

const getRateLimitConfig = () => rateLimitConfig;

// ============================================================
// 10. DARK MODE
// ============================================================

const getThemePreference = (userId) => {
  // In production, fetch from database
  return 'light';
};

const setThemePreference = (userId, theme) => {
  // In production, save to database
  return { userId, theme };
};

module.exports = {
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
  verify2FA,
  updateRateLimit,
  getRateLimitConfig,
  getThemePreference,
  setThemePreference
};
