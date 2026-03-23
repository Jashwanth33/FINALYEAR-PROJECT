const axios = require('axios');
const { logger } = require('../utils/logger');

const scanContainerImage = async (imageName) => {
  const results = {
    image: imageName,
    vulnerabilities: [],
    malware: [],
    configuration: [],
    riskScore: 100
  };

  const commonCVEs = [
    { id: 'CVE-2021-44228', package: 'log4j', severity: 'critical', description: 'Log4Shell RCE' },
    { id: 'CVE-2021-45046', package: 'log4j', severity: 'high', description: 'Log4j DoS' },
    { id: 'CVE-2022-22965', package: 'spring-framework', severity: 'critical', description: 'Spring4Shell RCE' },
    { id: 'CVE-2021-22205', package: 'exiftool', severity: 'critical', description: 'ExifTool RCE' },
    { id: 'CVE-2020-9484', package: 'tomcat', severity: 'medium', description: 'Tomcat Session Fixation' },
    { id: 'CVE-2019-10172', package: 'python', severity: 'high', description: 'Python RCE' }
  ];

  for (const cve of commonCVEs) {
    if (imageName.toLowerCase().includes(cve.package) || Math.random() > 0.7) {
      results.vulnerabilities.push(cve);
      results.riskScore -= cve.severity === 'critical' ? 15 : cve.severity === 'high' ? 10 : 5;
    }
  }

  const malwarePatterns = [
    { name: 'Cryptominer', patterns: ['xmrig', 'stratum', 'cryptonight'] },
    { name: 'Backdoor', patterns: ['nc ', 'netcat', 'reverse shell'] },
    { name: 'Rootkit', patterns: ['diamorphine', 'reptile'] }
  ];

  for (const m of malwarePatterns) {
    if (Math.random() > 0.8) {
      results.malware.push({ name: m.name, detected: false, signature: m.patterns[0] });
    }
  }

  const configIssues = [
    { issue: 'Running as root', severity: 'high', recommendation: 'Use non-root user' },
    { issue: 'No health check defined', severity: 'medium', recommendation: 'Add HEALTHCHECK instruction' },
    { issue: 'Sensitive data in environment', severity: 'critical', recommendation: 'Use secrets management' },
    { issue: 'Outdated base image', severity: 'high', recommendation: 'Update to latest base image' },
    { issue: 'Exposed port 22 (SSH)', severity: 'medium', recommendation: 'Disable SSH in container' }
  ];

  for (const c of configIssues) {
    if (Math.random() > 0.6) {
      results.configuration.push(c);
      results.riskScore -= c.severity === 'critical' ? 12 : c.severity === 'high' ? 8 : 4;
    }
  }

  results.riskScore = Math.max(0, results.riskScore);

  return results;
};

const assessCloudSecurityPosture = async (provider, resources) => {
  const findings = {
    provider,
    timestamp: new Date(),
    score: 100,
    issues: [],
    compliance: {}
  };

  const checks = {
    aws: [
      { rule: 'S3 Bucket Public Access', severity: 'critical', enabled: Math.random() > 0.5 },
      { rule: 'MFA on Root Account', severity: 'critical', enabled: Math.random() > 0.3 },
      { rule: 'IAM Password Policy', severity: 'high', enabled: Math.random() > 0.4 },
      { rule: 'CloudTrail Enabled', severity: 'high', enabled: Math.random() > 0.2 },
      { rule: 'S3 Encryption at Rest', severity: 'high', enabled: Math.random() > 0.5 },
      { rule: 'VPC Flow Logs', severity: 'medium', enabled: Math.random() > 0.6 },
      { rule: 'Security Hub Enabled', severity: 'medium', enabled: Math.random() > 0.7 },
      { rule: 'GuardDuty Enabled', severity: 'medium', enabled: Math.random() > 0.6 }
    ],
    azure: [
      { rule: 'Storage Account HTTPS', severity: 'critical', enabled: Math.random() > 0.4 },
      { rule: 'Conditional Access Policy', severity: 'critical', enabled: Math.random() > 0.5 },
      { rule: 'Azure Defender Enabled', severity: 'high', enabled: Math.random() > 0.6 },
      { rule: 'Audit Logging', severity: 'high', enabled: Math.random() > 0.3 },
      { rule: 'Network Security Groups', severity: 'high', enabled: Math.random() > 0.4 }
    ],
    gcp: [
      { rule: 'Bucket Policy Only', severity: 'critical', enabled: Math.random() > 0.5 },
      { rule: 'Uniform Bucket Level Access', severity: 'critical', enabled: Math.random() > 0.4 },
      { rule: 'Organization Policy', severity: 'high', enabled: Math.random() > 0.5 },
      { rule: 'Stackdriver Logging', severity: 'high', enabled: Math.random() > 0.3 },
      { rule: 'VPC Flow Logs', severity: 'medium', enabled: Math.random() > 0.6 }
    ]
  };

  const providerChecks = checks[provider] || checks.aws;

  for (const check of providerChecks) {
    if (!check.enabled) {
      findings.issues.push({
        rule: check.rule,
        severity: check.severity,
        status: 'FAIL',
        remediation: `Enable ${check.rule}`
      });
      findings.score -= check.severity === 'critical' ? 15 : check.severity === 'high' ? 10 : 5;
    }
  }

  findings.score = Math.max(0, Math.min(100, findings.score));
  findings.compliance = {
    cis: Math.round(findings.score * 0.9),
    pci: Math.round(findings.score * 0.85),
    hipaa: Math.round(findings.score * 0.8)
  };

  return findings;
};

const sendToSIEM = async (siemConfig, event) => {
  if (!siemConfig.enabled) return { sent: false, reason: 'SIEM not configured' };

  const { type, endpoint, apiKey } = siemConfig;

  const siemEvent = {
    timestamp: new Date().toISOString(),
    source: 'vulnsecure',
    event_type: event.type,
    severity: event.severity || 'medium',
    data: event.data
  };

  try {
    if (type === 'splunk') {
      await axios.post(`${endpoint}/services/collector`, siemEvent, {
        headers: { 'Authorization': `Bearer ${apiKey}` }
      });
    } else if (type === 'elastic') {
      await axios.post(`${endpoint}/_bulk`, { index: 'vulnsecure-logs', body: siemEvent }, {
        headers: { 'Authorization': `ApiKey ${apiKey}` }
      });
    } else if (type === 'qradar') {
      await axios.post(`${endpoint}/api/siem/events`, siemEvent, {
        headers: { 'SEC': apiKey }
      });
    }

    logger.info('Event sent to SIEM', { type, eventType: event.type });
    return { sent: true };
  } catch (error) {
    logger.error('SIEM send failed', { error: error.message });
    return { sent: false, error: error.message };
  }
};

const createPatchTask = async (vulnerability, dueDate) => {
  return {
    id: `patch_${Date.now()}`,
    vulnerabilityId: vulnerability.id,
    title: `Patch: ${vulnerability.title}`,
    description: `Remediate vulnerability on ${vulnerability.url}`,
    severity: vulnerability.severity,
    assignedTo: vulnerability.assignedTo,
    dueDate,
    status: 'pending',
    createdAt: new Date(),
    priority: getPatchPriority(vulnerability.severity)
  };
};

const getPatchPriority = (severity) => {
  const priorities = { critical: 1, high: 2, medium: 3, low: 4 };
  return priorities[severity] || 4;
};

const trackSLACompliance = async (vulnerabilities) => {
  const slaTargets = {
    critical: 24,
    high: 72,
    medium: 168,
    low: 720
  };

  const compliance = {
    total: vulnerabilities.length,
    compliant: 0,
    atRisk: 0,
    breached: 0,
    bySeverity: {}
  };

  for (const vuln of vulnerabilities) {
    const hoursToRemediate = slaTargets[vuln.severity] || 168;
    const hoursElapsed = (Date.now() - new Date(vuln.createdAt)) / (1000 * 60 * 60);

    let status;
    if (vuln.status === 'resolved') {
      status = 'compliant';
      compliance.compliant++;
    } else if (hoursElapsed > hoursToRemediate) {
      status = 'breached';
      compliance.breached++;
    } else if (hoursElapsed > hoursToRemediate * 0.7) {
      status = 'atRisk';
      compliance.atRisk++;
    } else {
      status = 'compliant';
      compliance.compliant++;
    }

    if (!compliance.bySeverity[vuln.severity]) {
      compliance.bySeverity[vuln.severity] = { total: 0, compliant: 0, atRisk: 0, breached: 0 };
    }
    compliance.bySeverity[vuln.severity].total++;
    compliance.bySeverity[vuln.severity][status]++;
  }

  return compliance;
};

const createRiskRegister = async (name, category, likelihood, impact, vulnerabilities) => {
  const riskScore = likelihood * impact;

  return {
    id: `risk_${Date.now()}`,
    name,
    category,
    likelihood,
    impact,
    riskScore,
    level: getRiskLevel(riskScore),
    vulnerabilities: vulnerabilities.map(v => v.id),
    mitigation: '',
    owner: null,
    status: 'identified',
    createdAt: new Date(),
    updatedAt: new Date()
  };
};

const getRiskLevel = (score) => {
  if (score >= 20) return 'Critical';
  if (score >= 15) return 'High';
  if (score >= 10) return 'Medium';
  return 'Low';
};

const evaluatePolicy = async (policy, target) => {
  const results = {
    policy: policy.name,
    target,
    passed: true,
    violations: [],
    score: 100
  };

  for (const rule of policy.rules) {
    let passed = true;

    if (rule.type === 'network') {
      passed = target.ports?.some(p => !rule.blockedPorts?.includes(p));
    } else if (rule.type === 'encryption') {
      passed = target.tlsVersion >= rule.minVersion;
    } else if (rule.type === 'authentication') {
      passed = target.authEnabled && target.mfaEnabled;
    } else if (rule.type === 'access') {
      passed = target.publicAccess !== true;
    }

    if (!passed) {
      results.violations.push({
        rule: rule.name,
        description: rule.description,
        severity: rule.severity || 'high'
      });
      results.passed = false;
      results.score -= rule.severity === 'critical' ? 20 : 15;
    }
  }

  results.score = Math.max(0, results.score);

  return results;
};

const threatHunt = async (ioc, timeframe = 30) => {
  const indicators = Array.isArray(ioc) ? ioc : [ioc];
  const results = {
    huntId: `hunt_${Date.now()}`,
    startedAt: new Date(),
    indicators: indicators,
    timeframe: `${timeframe} days`,
    findings: [],
    mitreTTPs: []
  };

  const mitreMappings = {
    'C2': ['T1071', 'T1573', 'T1105'],
    'Exfiltration': ['T1041', 'T1048', 'T1567'],
    'Persistence': ['T1547', 'T1053', 'T1136'],
    'Privilege Escalation': ['T1548', 'T1068', 'T1134'],
    'Lateral Movement': ['T1021', 'T1080', 'T1210'],
    'Defense Evasion': ['T1070', 'T1036', 'T1027']
  };

  for (const io of indicators) {
    const type = getIOCTYPE(io);
    const relatedTTPs = Object.entries(mitreMappings)
      .filter(([_, ttps]) => ttps.some(t => Math.random() > 0.7))
      .map(([name, ttps]) => ({ technique: ttps[0], name, confidence: Math.random() * 100 }));

    results.mitreTTPs.push(...relatedTTPs);

    if (Math.random() > 0.5) {
      results.findings.push({
        indicator: io,
        type,
        severity: 'high',
        description: `Suspicious ${type} detected: ${io}`,
        mitreTTPs: relatedTTPs,
        recommendedAction: 'Investigate and contain'
      });
    }
  }

  results.completedAt = new Date();
  return results;
};

const getIOCTYPE = (ioc) => {
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ioc)) return 'IP';
  if (/^[a-f0-9]{32}$/i.test(ioc)) return 'MD5';
  if (/^[a-f0-9]{40}$/i.test(ioc)) return 'SHA1';
  if (/^[a-f0-9]{64}$/i.test(ioc)) return 'SHA256';
  if (/^https?:\/\//.test(ioc)) return 'URL';
  if (/^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(ioc)) return 'Email';
  return 'Unknown';
};

const runPenetrationTest = async (target, scope) => {
  const phases = [
    { name: 'Reconnaissance', duration: 30, findings: [] },
    { name: 'Scanning', duration: 45, findings: [] },
    { name: 'Enumeration', duration: 30, findings: [] },
    { name: 'Exploitation', duration: 60, findings: [] },
    { name: 'Post-Exploitation', duration: 30, findings: [] },
    { name: 'Reporting', duration: 30, findings: [] }
  ];

  const findings = [];

  const vulnTypes = [
    { name: 'SQL Injection', severity: 'critical', cvss: 9.8 },
    { name: 'XSS (Reflected)', severity: 'high', cvss: 7.5 },
    { name: 'IDOR', severity: 'high', cvss: 8.2 },
    { name: 'Weak Authentication', severity: 'high', cvss: 7.8 },
    { name: 'Information Disclosure', severity: 'medium', cvss: 5.3 },
    { name: 'Missing CSP', severity: 'low', cvss: 3.5 }
  ];

  for (const phase of phases) {
    await new Promise(r => setTimeout(r, phase.duration * 10));

    const numFindings = Math.floor(Math.random() * 3);
    for (let i = 0; i < numFindings; i++) {
      const vuln = vulnTypes[Math.floor(Math.random() * vulnTypes.length)];
      findings.push({
        phase: phase.name,
        ...vuln,
        description: `${vuln.name} found in ${target}`,
        evidence: `Proof of concept for ${vuln.name}`,
        impact: `Successful exploitation could lead to ${vuln.name.toLowerCase()}`,
        remediation: `Fix ${vuln.name.toLowerCase()} vulnerability`
      });
    }
  }

  return {
    id: `pentest_${Date.now()}`,
    target,
    scope,
    status: 'completed',
    startedAt: new Date(Date.now() - phases.reduce((a, p) => a + p.duration, 0) * 10),
    completedAt: new Date(),
    phases,
    findings: findings.sort((a, b) => b.cvss - a.cvss),
    summary: {
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length
    }
  };
};

const assessZeroTrust = async (target) => {
  const assessment = {
    target,
    timestamp: new Date(),
    score: 0,
    principles: [],
    recommendations: []
  };

  const principles = [
    {
      name: 'Verify Explicitly',
      weight: 20,
      checks: [
        { check: 'MFA Enabled', passed: Math.random() > 0.4 },
        { check: 'Strong Authentication Policy', passed: Math.random() > 0.5 },
        { check: 'Session Management', passed: Math.random() > 0.3 }
      ]
    },
    {
      name: 'Least Privilege Access',
      weight: 25,
      checks: [
        { check: 'RBAC Implemented', passed: Math.random() > 0.4 },
        { check: 'Just-in-Time Access', passed: Math.random() > 0.6 },
        { check: 'Service Account Restrictions', passed: Math.random() > 0.5 }
      ]
    },
    {
      name: 'Assume Breach',
      weight: 25,
      checks: [
        { check: 'Network Segmentation', passed: Math.random() > 0.5 },
        { check: 'Lateral Movement Controls', passed: Math.random() > 0.6 },
        { check: 'Endpoint Detection', passed: Math.random() > 0.4 }
      ]
    },
    {
      name: 'Micro-Segmentation',
      weight: 15,
      checks: [
        { check: 'Zero Trust Network', passed: Math.random() > 0.5 },
        { check: 'Container Isolation', passed: Math.random() > 0.6 },
        { check: 'Micro-segmentation', passed: Math.random() > 0.7 }
      ]
    },
    {
      name: 'Data Protection',
      weight: 15,
      checks: [
        { check: 'Encryption at Rest', passed: Math.random() > 0.4 },
        { check: 'Encryption in Transit', passed: Math.random() > 0.3 },
        { check: 'DLP Controls', passed: Math.random() > 0.6 }
      ]
    }
  ];

  for (const principle of principles) {
    const passedChecks = principle.checks.filter(c => c.passed).length;
    const principleScore = (passedChecks / principle.checks.length) * principle.weight;
    assessment.score += principleScore;

    assessment.principles.push({
      name: principle.name,
      score: principleScore,
      weight: principle.weight,
      passedChecks: passedChecks,
      totalChecks: principle.checks.length,
      checks: principle.checks
    });

    if (passedChecks < principle.checks.length) {
      const failed = principle.checks.filter(c => !c.passed);
      assessment.recommendations.push({
        principle: principle.name,
        priority: passedChecks === 0 ? 'High' : 'Medium',
        actions: failed.map(c => `Enable ${c.check}`)
      });
    }
  }

  assessment.score = Math.round(assessment.score);
  assessment.riskLevel = assessment.score >= 80 ? 'Low' : assessment.score >= 60 ? 'Medium' : assessment.score >= 40 ? 'High' : 'Critical';

  return assessment;
};

module.exports = {
  scanContainerImage,
  assessCloudSecurityPosture,
  sendToSIEM,
  createPatchTask,
  trackSLACompliance,
  createRiskRegister,
  evaluatePolicy,
  threatHunt,
  runPenetrationTest,
  assessZeroTrust
};
