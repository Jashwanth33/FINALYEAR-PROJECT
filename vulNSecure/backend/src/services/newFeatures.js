const fs = require('fs');
const path = require('path');
const cron = require('node-cron');
const { Scan, Vulnerability, User, ScheduledScan } = require('../models');
const { logger } = require('../utils/logger');

// ============================================================
// 1. PDF REPORT EXPORT
// ============================================================

const generatePDFReport = async (scanId, userId) => {
  const scan = await Scan.findByPk(scanId, {
    include: [
      { model: Vulnerability, as: 'vulnerabilities' },
      { model: User, as: 'user' }
    ]
  });
  
  if (!scan) throw new Error('Scan not found');
  
  const vulns = scan.vulnerabilities || [];
  const summary = {
    critical: vulns.filter(v => v.severity === 'critical').length,
    high: vulns.filter(v => v.severity === 'high').length,
    medium: vulns.filter(v => v.severity === 'medium').length,
    low: vulns.filter(v => v.severity === 'low').length,
    total: vulns.length
  };
  
  const html = `<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<title>Security Report - ${scan.name}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: Arial, sans-serif; padding: 40px; color: #333; }
  .header { text-align: center; margin-bottom: 30px; border-bottom: 3px solid #2563eb; padding-bottom: 20px; }
  .header h1 { color: #1e40af; font-size: 28px; margin-bottom: 10px; }
  .header p { color: #666; font-size: 14px; }
  .summary { display: flex; gap: 15px; margin-bottom: 30px; }
  .box { flex: 1; padding: 20px; border-radius: 8px; text-align: center; }
  .box.total { background: #f8fafc; border: 2px solid #e2e8f0; }
  .box.critical { background: #fef2f2; border: 2px solid #fecaca; }
  .box.high { background: #fff7ed; border: 2px solid #fed7aa; }
  .box.medium { background: #fefce8; border: 2px solid #fef08a; }
  .box.low { background: #f0fdf4; border: 2px solid #bbf7d0; }
  .box h2 { font-size: 36px; margin-bottom: 5px; }
  .box.total h2 { color: #1e40af; }
  .box.critical h2 { color: #dc2626; }
  .box.high h2 { color: #ea580c; }
  .box.medium h2 { color: #ca8a04; }
  .box.low h2 { color: #16a34a; }
  .vuln { margin-bottom: 25px; border: 1px solid #e5e7eb; border-radius: 8px; overflow: hidden; page-break-inside: avoid; }
  .vuln-header { padding: 12px 15px; display: flex; align-items: center; gap: 10px; }
  .vuln-header.critical { background: #fef2f2; }
  .vuln-header.high { background: #fff7ed; }
  .vuln-header.medium { background: #fefce8; }
  .vuln-header.low { background: #f0fdf4; }
  .badge { padding: 4px 10px; border-radius: 15px; font-size: 11px; font-weight: bold; color: white; }
  .badge.critical { background: #dc2626; }
  .badge.high { background: #ea580c; }
  .badge.medium { background: #ca8a04; }
  .badge.low { background: #16a34a; }
  .vuln-body { padding: 15px; }
  .vuln-body h4 { color: #374151; margin: 10px 0 5px; font-size: 13px; }
  .vuln-body p { color: #6b7280; font-size: 13px; line-height: 1.5; }
  .code { background: #1f2937; color: #f3f4f6; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 12px; white-space: pre-wrap; margin-top: 8px; }
  .info { display: flex; gap: 20px; margin-bottom: 10px; font-size: 12px; }
  .info span { color: #6b7280; }
  .info strong { color: #374151; }
  .footer { margin-top: 40px; text-align: center; color: #9ca3af; font-size: 11px; border-top: 1px solid #e5e7eb; padding-top: 15px; }
</style>
</head><body>
  <div class="header">
    <h1>Security Assessment Report</h1>
    <p><strong>Target:</strong> ${scan.target} | <strong>Date:</strong> ${new Date().toLocaleDateString()} | <strong>Scanner:</strong> vulNSecure</p>
  </div>

  <h2 style="margin-bottom:15px;">Executive Summary</h2>
  <p style="margin-bottom:20px;color:#4b5563;">
    This report presents findings from a security assessment of <strong>${scan.target}</strong>. 
    A total of <strong>${summary.total}</strong> vulnerabilities were identified: 
    <strong>${summary.critical}</strong> critical, <strong>${summary.high}</strong> high, 
    <strong>${summary.medium}</strong> medium, and <strong>${summary.low}</strong> low severity issues.
  </p>

  <div class="summary">
    <div class="box total"><h2>${summary.total}</h2><p>Total</p></div>
    <div class="box critical"><h2>${summary.critical}</h2><p>Critical</p></div>
    <div class="box high"><h2>${summary.high}</h2><p>High</p></div>
    <div class="box medium"><h2>${summary.medium}</h2><p>Medium</p></div>
    <div class="box low"><h2>${summary.low}</h2><p>Low</p></div>
  </div>

  <h2 style="margin-bottom:15px;">Detailed Findings</h2>
  
  ${vulns.map((v, i) => `
  <div class="vuln">
    <div class="vuln-header ${v.severity}">
      <span class="badge ${v.severity}">${v.severity.toUpperCase()}</span>
      <h3 style="font-size:16px;">${i+1}. ${v.title}</h3>
    </div>
    <div class="vuln-body">
      <div class="info">
        <span><strong>URL:</strong> ${v.url || 'N/A'}</span>
        <span><strong>CVSS:</strong> ${v.cvssScore || 'N/A'}</span>
        <span><strong>CWE:</strong> ${v.cveId || 'N/A'}</span>
      </div>
      <h4>Description</h4><p>${v.description}</p>
      <h4>Evidence</h4><p>${v.evidence || 'N/A'}</p>
      <h4>Remediation</h4><p>${v.solution}</p>
      ${v.poc ? `<h4>Proof of Concept</h4><div class="code">${v.poc}</div>` : ''}
    </div>
  </div>
  `).join('')}

  <div class="footer">
    <p>Generated by vulNSecure - Confidential</p>
  </div>
</body></html>`;
  
  const reportsDir = path.join(__dirname, '../../reports');
  if (!fs.existsSync(reportsDir)) fs.mkdirSync(reportsDir, { recursive: true });
  
  const fileName = `report-${scanId}-${Date.now()}.html`;
  const filePath = path.join(reportsDir, fileName);
  fs.writeFileSync(filePath, html);
  
  return { filePath, fileName, summary };
};

// ============================================================
// 2. EMAIL NOTIFICATIONS
// ============================================================

const sendEmailNotification = async (type, data) => {
  const notifications = {
    'vulnerability_found': {
      subject: `Critical Vulnerability Found: ${data.title}`,
      body: `
A new vulnerability was detected:

Title: ${data.title}
Severity: ${data.severity.toUpperCase()}
CVSS Score: ${data.cvssScore || 'N/A'}
URL: ${data.url}

Description:
${data.description}

Remediation:
${data.solution}

View details: http://localhost:3000/vulnerabilities/${data.id}
      `
    },
    'scan_complete': {
      subject: `Scan Complete: ${data.name}`,
      body: `
Your security scan has completed:

Target: ${data.target}
Status: ${data.status}
Total Issues: ${data.summary?.total || 0}
- Critical: ${data.summary?.critical || 0}
- High: ${data.summary?.high || 0}
- Medium: ${data.summary?.medium || 0}
- Low: ${data.summary?.low || 0}

View report: http://localhost:3000/scans/${data.id}
      `
    },
    'weekly_summary': {
      subject: 'Weekly Security Summary',
      body: `
Weekly Security Report:

Total Scans This Week: ${data.scans || 0}
Total Vulnerabilities: ${data.vulns || 0}
Critical Issues: ${data.critical || 0}
Fixed Issues: ${data.fixed || 0}

Login to view full details: http://localhost:3000/dashboard
      `
    }
  };
  
  const notification = notifications[type] || { subject: 'Security Alert', body: JSON.stringify(data) };
  
  // Store notification in database
  const { Notification } = require('../models');
  await Notification.create({
    userId: data.userId || null,
    type,
    title: notification.subject,
    message: notification.body,
    data: data,
    read: false
  });
  
  logger.info('Notification created: ' + notification.subject);
  return { success: true, notification };
};

// ============================================================
// 3. SCHEDULED SCANNING
// ============================================================

const scheduledJobs = new Map();

const initScheduledScans = async () => {
  try {
    const schedules = await ScheduledScan.findAll({ where: { enabled: true } });
    for (const schedule of schedules) {
      startSchedule(schedule);
    }
    logger.info('Initialized ' + schedules.length + ' scheduled scans');
  } catch (e) {
    logger.error('Failed to init scheduled scans: ' + e.message);
  }
};

const startSchedule = (schedule) => {
  const cronExpr = getCronExpression(schedule.frequency, schedule.dayOfWeek, schedule.time);
  if (!cronExpr) return;
  
  if (scheduledJobs.has(schedule.id)) {
    scheduledJobs.get(schedule.id).stop();
  }
  
  const job = cron.schedule(cronExpr, async () => {
    logger.info('Running scheduled scan: ' + schedule.target);
    
    try {
      const scan = await Scan.create({
        userId: schedule.userId,
        name: 'Scheduled: ' + schedule.name,
        target: schedule.target,
        type: schedule.type || 'web',
        status: 'running'
      });
      
      const { performScan } = require('./scannerService');
      await performScan(schedule.target, scan.id);
      
      const vulns = await Vulnerability.findAll({ where: { scanId: scan.id } });
      await scan.update({
        status: 'completed',
        progress: 100,
        endTime: new Date(),
        summary: {
          critical: vulns.filter(v => v.severity === 'critical').length,
          high: vulns.filter(v => v.severity === 'high').length,
          medium: vulns.filter(v => v.severity === 'medium').length,
          low: vulns.filter(v => v.severity === 'low').length,
          total: vulns.length
        }
      });
      
      await ScheduledScan.update({ lastRunAt: new Date() }, { where: { id: schedule.id } });
      
      // Send notification
      await sendEmailNotification('scan_complete', scan.toJSON());
      
    } catch (e) {
      logger.error('Scheduled scan failed: ' + e.message);
    }
  });
  
  scheduledJobs.set(schedule.id, job);
};

const getCronExpression = (frequency, dayOfWeek, time) => {
  const [hour, minute] = (time || '02:00').split(':');
  const days = { sunday: 0, monday: 1, tuesday: 2, wednesday: 3, thursday: 4, friday: 5, saturday: 6 };
  
  switch (frequency) {
    case 'daily': return `${minute} ${hour} * * *`;
    case 'weekly': return `${minute} ${hour} * * ${days[dayOfWeek] || 1}`;
    case 'monthly': return `${minute} ${hour} 1 * *`;
    default: return null;
  }
};

const createSchedule = async (data) => {
  const schedule = await ScheduledScan.create({
    userId: data.userId,
    name: data.name,
    target: data.target,
    type: data.type || 'web',
    frequency: data.frequency,
    dayOfWeek: data.dayOfWeek,
    time: data.time,
    enabled: true
  });
  
  startSchedule(schedule);
  return schedule;
};

// ============================================================
// 4. REAL-TIME DASHBOARD STATS
// ============================================================

const getDashboardStats = async (userId) => {
  const totalScans = await Scan.count({ where: { userId } });
  const completedScans = await Scan.count({ where: { userId, status: 'completed' } });
  const runningScans = await Scan.count({ where: { userId, status: 'running' } });
  const failedScans = await Scan.count({ where: { userId, status: 'failed' } });
  
  const totalVulns = await Vulnerability.count();
  const criticalVulns = await Vulnerability.count({ where: { severity: 'critical' } });
  const highVulns = await Vulnerability.count({ where: { severity: 'high' } });
  const mediumVulns = await Vulnerability.count({ where: { severity: 'medium' } });
  const lowVulns = await Vulnerability.count({ where: { severity: 'low' } });
  
  const recentScans = await Scan.findAll({
    where: { userId },
    order: [['createdAt', 'DESC']],
    limit: 5
  });
  
  const recentVulns = await Vulnerability.findAll({
    order: [['createdAt', 'DESC']],
    limit: 10
  });
  
  return {
    scans: { total: totalScans, completed: completedScans, running: runningScans, failed: failedScans },
    vulnerabilities: { total: totalVulns, critical: criticalVulns, high: highVulns, medium: mediumVulns, low: lowVulns },
    recentScans,
    recentVulns,
    riskScore: calculateRiskScore(criticalVulns, highVulns, mediumVulns, lowVulns)
  };
};

const calculateRiskScore = (critical, high, medium, low) => {
  const score = (critical * 10) + (high * 7) + (medium * 4) + (low * 1);
  return Math.min(score, 100);
};

module.exports = {
  generatePDFReport,
  sendEmailNotification,
  initScheduledScans,
  createSchedule,
  getDashboardStats
};
