const axios = require('axios');
const dns = require('dns').promises;
const fs = require('fs');
const path = require('path');
const { logger } = require('../utils/logger');

class WebhookManager {
  constructor() {
    this.webhooks = new Map();
  }

  async registerWebhook(id, url, events, secret) {
    this.webhooks.set(id, { url, events, secret, createdAt: new Date() });
    return { id, url, events };
  }

  async trigger(event, data) {
    for (const [id, webhook] of this.webhooks) {
      if (webhook.events.includes(event) || webhook.events.includes('*')) {
        try {
          await axios.post(webhook.url, { event, data, timestamp: new Date() }, {
            headers: webhook.secret ? { 'X-Webhook-Secret': webhook.secret } : {},
            timeout: 5000
          });
          logger.info('Webhook triggered', { event, webhookId: id });
        } catch (error) {
          logger.error('Webhook failed', { event, webhookId: id, error: error.message });
        }
      }
    }
  }

  listWebhooks() {
    return Array.from(this.webhooks.entries()).map(([id, w]) => ({
      id, url: w.url, events: w.events, createdAt: w.createdAt
    }));
  }

  deleteWebhook(id) {
    return this.webhooks.delete(id);
  }
}

const webhookManager = new WebhookManager();

const checkMalwarePhishing = async (url) => {
  const results = { malicious: false, threats: [], score: 0 };
  
  const suspiciousPatterns = [
    { pattern: /login|signin|account|verify|secure|update/i, type: 'phishing', weight: 30 },
    { pattern: /\.xyz|\.top|\.work|\.click|\.loan/i, type: 'suspicious_tld', weight: 20 },
    { pattern: /bitcoin|crypto|wallet|mining/i, type: 'cryptocurrency', weight: 25 },
    { pattern: /free|gift|prize|win|claim/i, type: 'social_engineering', weight: 20 },
    { pattern: /password|credential|login|auth/i, type: 'credential_phishing', weight: 40 }
  ];

  let threatScore = 0;
  for (const { pattern, type, weight } of suspiciousPatterns) {
    if (pattern.test(url)) {
      results.threats.push({ type, weight });
      threatScore += weight;
    }
  }

  results.score = Math.min(100, threatScore);
  results.malicious = threatScore >= 30;

  return results;
};

const checkDNSBL = async (ip) => {
  const blocklists = [
    { name: 'Spamhaus', zone: 'zen.spamhaus.org' },
    { name: 'Sorbs', zone: 'dnsbl.sorbs.net' },
    { name: 'Barracuda', zone: 'b.barracudacentral.org' },
    { name: 'SpamCop', zone: 'bl.spamcop.net' },
    { name: 'UCEPROTECT', zone: 'dnsbl-1.uceprotect.net' }
  ];

  const results = { ip, blacklisted: false, listings: [] };

  const reverseIP = ip.split('.').reverse().join('.');

  for (const bl of blocklists) {
    try {
      const resolved = await dns.resolve(`${reverseIP}.${bl.zone}`);
      if (resolved && resolved.length > 0) {
        results.blacklisted = true;
        results.listings.push({
          blocklist: bl.name,
          zone: bl.zone,
          reason: resolved[0] || 'Listed'
        });
      }
    } catch {
      // Not listed
    }
  }

  return results;
};

const scanForSecrets = async (targetUrl) => {
  const secrets = [];
  
  const secretPatterns = [
    { pattern: /api[_-]?key["\s:=]+[a-zA-Z0-9]{20,}/i, type: 'API Key', severity: 'critical' },
    { pattern: /aws[_-]?access[_-]?key["\s:=]+[a-zA-Z0-9]{20,}/i, type: 'AWS Key', severity: 'critical' },
    { pattern: /github[_-]?token["\s:=]+[a-zA-Z0-9]{36,}/i, type: 'GitHub Token', severity: 'critical' },
    { pattern: /bearer\s+[a-zA-Z0-9\-_\.]+/i, type: 'Bearer Token', severity: 'high' },
    { pattern: /private[_-]?key["\s:=]+-----BEGIN/i, type: 'Private Key', severity: 'critical' },
    { pattern: /password["\s:=]+[^\s"<>]{8,}/i, type: 'Password', severity: 'high' },
    { pattern: /slack[_-]?token["\s:=]+xox[baprs]-[0-9]{10,}/i, type: 'Slack Token', severity: 'high' },
    { pattern: /stripe[_-]?sk["\s:=]+[a-zA-Z0-9]{24,}/i, type: 'Stripe Key', severity: 'critical' },
    { pattern: /firebase[_-]?key["\s:=]+[a-zA-Z0-9_-]{30,}/i, type: 'Firebase Key', severity: 'high' },
    { pattern: /sendgrid[_-]?api[_-]?key["\s:=]+[a-zA-Z0-9]{20,}/i, type: 'SendGrid Key', severity: 'high' }
  ];

  try {
    const response = await axios.get(targetUrl, { timeout: 10000 });
    const content = response.data.toString();

    for (const { pattern, type, severity } of secretPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        secrets.push({ type, severity, match: matches[0].substring(0, 50), url: targetUrl });
      }
    }

    // Check common sensitive files
    const sensitiveFiles = ['/.env', '/.git/config', '/wp-config.php', '/config.php', '/settings.py'];
    for (const file of sensitiveFiles) {
      try {
        const fileUrl = targetUrl.replace(/\/$/, '') + file;
        const fileResponse = await axios.get(fileUrl, { timeout: 5000 });
        if (fileResponse.status === 200 && fileResponse.data) {
          secrets.push({ type: 'Exposed File', severity: 'high', file, url: fileUrl });
        }
      } catch {}
    }
  } catch (error) {
    logger.error('Secret scanning failed', { targetUrl, error: error.message });
  }

  return secrets;
};

const OrganizationModel = {
  id: null,
  name: '',
  settings: {},
  members: [],
  createdAt: new Date()
};

const createOrganization = async (name, ownerId) => {
  return {
    id: `org_${Date.now()}`,
    name,
    ownerId,
    settings: {
      maxScans: 100,
      maxAssets: 50,
      webhookUrl: null,
      slackWebhook: null
    },
    members: [{ userId: ownerId, role: 'owner' }],
    createdAt: new Date()
  };
};

const checkPluginCompatibility = (plugin) => {
  const requiredFields = ['name', 'version', 'scan', 'execute'];
  const missing = requiredFields.filter(f => !plugin[f]);
  return { valid: missing.length === 0, missing };
};

const executePlugin = async (plugin, target, options) => {
  const compatibility = checkPluginCompatibility(plugin);
  if (!compatibility.valid) {
    throw new Error(`Plugin invalid: missing ${compatibility.missing.join(', ')}`);
  }

  try {
    const result = await plugin.execute(target, options, {
      axios,
      logger
    });
    return { success: true, results: result };
  } catch (error) {
    return { success: false, error: error.message };
  }
};

const exportData = async (userId, format = 'json') => {
  const { Scan, Vulnerability, Asset, Report } = require('../models');
  
  const data = {
    exportedAt: new Date(),
    userId,
    scans: await Scan.findAll({ where: { userId }, raw: true }),
    assets: await Asset.findAll({ where: { userId }, raw: true }),
    reports: await Report.findAll({ where: { userId }, raw: true })
  };

  if (format === 'json') {
    return JSON.stringify(data, null, 2);
  } else if (format === 'csv') {
    let csv = 'Scans\n';
    csv += Object.keys(data.scans[0] || {}).join(',') + '\n';
    for (const scan of data.scans) {
      csv += Object.values(scan).join(',') + '\n';
    }
    return csv;
  }

  return data;
};

const importData = async (userId, data, format = 'json') => {
  const { Scan, Asset } = require('../models');
  
  const results = { imported: 0, failed: 0, errors: [] };

  try {
    const parsed = typeof data === 'string' ? JSON.parse(data) : data;

    if (parsed.scans) {
      for (const scan of parsed.scans) {
        try {
          await Scan.create({ ...scan, userId, id: undefined });
          results.imported++;
        } catch (error) {
          results.failed++;
          results.errors.push({ scan: scan.name, error: error.message });
        }
      }
    }

    if (parsed.assets) {
      for (const asset of parsed.assets) {
        try {
          await Asset.create({ ...asset, userId, id: undefined });
          results.imported++;
        } catch (error) {
          results.failed++;
          results.errors.push({ asset: asset.name, error: error.message });
        }
      }
    }
  } catch (error) {
    results.errors.push({ error: 'Parse error: ' + error.message });
  }

  return results;
};

const RateLimitTracker = {
  requests: new Map(),
  
  track(ip, endpoint) {
    const key = `${ip}:${endpoint}`;
    const now = Date.now();
    const window = 60000;
    
    if (!this.requests.has(key)) {
      this.requests.set(key, []);
    }
    
    const timestamps = this.requests.get(key).filter(t => t > now - window);
    timestamps.push(now);
    this.requests.set(key, timestamps);
    
    return timestamps.length;
  },
  
  isRateLimited(ip, endpoint, limit = 100) {
    return this.track(ip, endpoint) > limit;
  },
  
  getStats(ip) {
    const stats = {};
    for (const [key, timestamps] of this.requests) {
      if (key.startsWith(ip + ':')) {
        const endpoint = key.split(':')[1];
        stats[endpoint] = timestamps.length;
      }
    }
    return stats;
  }
};

const generateSecurityReport = (scan, vulnerabilities) => {
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  
  for (const v of vulnerabilities) {
    severityCounts[v.severity] = (severityCounts[v.severity] || 0) + 1;
  }
  
  const riskScore = Math.max(0, 100 - 
    (severityCounts.critical * 10) - 
    (severityCounts.high * 7) - 
    (severityCounts.medium * 4) - 
    (severityCounts.low * 1)
  );
  
  const executiveSummary = {
    scanName: scan.name,
    target: scan.target,
    scanDate: scan.createdAt,
    riskScore,
    riskLevel: riskScore >= 80 ? 'Low' : riskScore >= 60 ? 'Medium' : riskScore >= 40 ? 'High' : 'Critical',
    vulnerabilitiesFound: vulnerabilities.length,
    severityBreakdown: severityCounts,
    topRecommendations: generateRecommendations(severityCounts)
  };
  
  return executiveSummary;
};

const generateRecommendations = (severityCounts) => {
  const recommendations = [];
  
  if (severityCounts.critical > 0) {
    recommendations.push({ priority: 'Critical', action: 'Immediately address critical vulnerabilities' });
  }
  if (severityCounts.high > 0) {
    recommendations.push({ priority: 'High', action: 'Plan remediation for high-severity issues' });
  }
  if (severityCounts.medium > 0) {
    recommendations.push({ priority: 'Medium', action: 'Schedule medium-severity fixes' });
  }
  
  recommendations.push({ priority: 'Ongoing', action: 'Implement continuous security monitoring' });
  recommendations.push({ priority: 'Ongoing', action: 'Conduct regular penetration testing' });
  
  return recommendations;
};

const detectAnomalies = async (target) => {
  const anomalies = [];
  
  try {
    const baselineResponse = await axios.get(target, { timeout: 5000 });
    const baselineSize = baselineResponse.data.length;
    const baselineTime = 200;
    
    const testPayloads = [
      { name: 'SQL Injection', payload: "' OR '1'='1" },
      { name: 'XSS', payload: '<script>alert(1)</script>' },
      { name: 'Path Traversal', payload: '../../../etc/passwd' }
    ];
    
    for (const { name, payload } of testPayloads) {
      try {
        const startTime = Date.now();
        const testUrl = `${target}?q=${encodeURIComponent(payload)}`;
        const response = await axios.get(testUrl, { timeout: 5000 });
        const responseTime = Date.now() - startTime;
        
        if (responseTime > baselineTime * 3) {
          anomalies.push({ type: 'Timing Anomaly', test: name, details: `Response time: ${responseTime}ms` });
        }
        
        if (Math.abs(response.data.length - baselineSize) > baselineSize * 0.5) {
          anomalies.push({ type: 'Response Size Anomaly', test: name, details: `Size changed significantly` });
        }
      } catch {}
    }
  } catch (error) {
    anomalies.push({ type: 'Baseline Error', details: error.message });
  }
  
  return anomalies;
};

module.exports = {
  webhookManager,
  checkMalwarePhishing,
  checkDNSBL,
  scanForSecrets,
  createOrganization,
  checkPluginCompatibility,
  executePlugin,
  exportData,
  importData,
  RateLimitTracker,
  generateSecurityReport,
  detectAnomalies
};
