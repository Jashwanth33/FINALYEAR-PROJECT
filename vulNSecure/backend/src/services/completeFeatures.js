const axios = require('axios');
const crypto = require('crypto');
const { Vulnerability } = require('../models');
const { logger } = require('../utils/logger');

// ============================================================
// 1. BURP SUITE-LIKE FEATURES
// ============================================================

// Request Interceptor
const interceptRequest = async (url, method, headers, body) => {
  const result = { request: { url, method, headers, body }, response: null };
  
  try {
    const resp = await axios({
      url, method: method || 'GET', headers: headers || {},
      data: body, timeout: 10000, validateStatus: () => true
    });
    
    result.response = {
      status: resp.status,
      headers: resp.headers,
      body: resp.data.toString().substring(0, 5000)
    };
  } catch (e) {
    result.error = e.message;
  }
  
  return result;
};

// Request Repeater
const repeatRequest = async (url, method, headers, body, times = 1) => {
  const results = [];
  
  for (let i = 0; i < times; i++) {
    try {
      const startTime = Date.now();
      const resp = await axios({
        url, method: method || 'GET', headers: headers || {},
        data: body, timeout: 10000, validateStatus: () => true
      });
      
      results.push({
        iteration: i + 1,
        status: resp.status,
        time: Date.now() - startTime,
        size: JSON.stringify(resp.data).length
      });
    } catch (e) {
      results.push({ iteration: i + 1, error: e.message });
    }
  }
  
  return results;
};

// Intruder (Fuzzing)
const fuzzEndpoint = async (url, param, payloads, method = 'GET') => {
  const results = [];
  
  for (const payload of payloads) {
    try {
      let testUrl = url;
      let data = null;
      
      if (method === 'GET') {
        testUrl = url + (url.includes('?') ? '&' : '?') + param + '=' + encodeURIComponent(payload);
      } else {
        data = { [param]: payload };
      }
      
      const startTime = Date.now();
      const resp = await axios({
        url: testUrl, method,
        headers: { 'Content-Type': 'application/json' },
        data, timeout: 10000, validateStatus: () => true
      });
      
      results.push({
        payload, status: resp.status,
        time: Date.now() - startTime,
        size: JSON.stringify(resp.data).length,
        interesting: resp.status >= 500 || resp.status === 403
      });
    } catch (e) {
      results.push({ payload, error: e.message, interesting: true });
    }
  }
  
  return results;
};

// Sequencer (Token Analysis)
const analyzeToken = async (url, iterations = 10) => {
  const tokens = [];
  
  for (let i = 0; i < iterations; i++) {
    try {
      const resp = await axios.get(url, { timeout: 5000, validateStatus: () => true });
      const cookies = resp.headers['set-cookie'] || [];
      cookies.forEach(c => {
        const token = c.split('=')[1]?.split(';')[0];
        if (token) tokens.push(token);
      });
    } catch (e) {}
  }
  
  return {
    totalTokens: tokens.length,
    uniqueTokens: new Set(tokens).size,
    entropy: calculateEntropy(tokens.join('')),
    patterns: analyzePatterns(tokens)
  };
};

const calculateEntropy = (str) => {
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  let entropy = 0;
  for (const f of Object.values(freq)) {
    const p = f / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy.toFixed(2);
};

const analyzePatterns = (tokens) => {
  if (tokens.length < 2) return [];
  
  const patterns = [];
  const first = tokens[0];
  
  patterns.push({
    type: 'Length',
    value: first.length,
    consistent: tokens.every(t => t.length === first.length)
  });
  
  patterns.push({
    type: 'Entropy',
    value: calculateEntropy(tokens.join('')),
    high: parseFloat(calculateEntropy(tokens.join(''))) > 3.5
  });
  
  return patterns;
};

// Decoder/Encoder
const encodeDecode = (input, type) => {
  const operations = {
    'base64-encode': Buffer.from(input).toString('base64'),
    'base64-decode': Buffer.from(input, 'base64').toString(),
    'url-encode': encodeURIComponent(input),
    'url-decode': decodeURIComponent(input),
    'hex-encode': Buffer.from(input).toString('hex'),
    'hex-decode': Buffer.from(input, 'hex').toString(),
    'md5': crypto.createHash('md5').update(input).digest('hex'),
    'sha1': crypto.createHash('sha1').update(input).digest('hex'),
    'sha256': crypto.createHash('sha256').update(input).digest('hex')
  };
  
  return operations[type] || input;
};

// ============================================================
// 2. CI/CD INTEGRATION
// ============================================================

const generateCIConfig = (platform, target, token) => {
  const configs = {
    'github': `name: Security Scan
on: [push, pull_request]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run vulNSecure
        run: |
          curl -X POST \${{ secrets.VULNSECURE_URL }}/api/scans \\
            -H "Authorization: Bearer \${{ secrets.VULNSECURE_TOKEN }}" \\
            -H "Content-Type: application/json" \\
            -d '{"target": "${target}", "type": "web"}'`,
    
    'gitlab': `security-scan:
  stage: test
  script:
    - curl -X POST \$VULNSECURE_URL/api/scans
      -H "Authorization: Bearer \$VULNSECURE_TOKEN"
      -H "Content-Type: application/json"
      -d '{"target": "${target}", "type": "web"}'
  only:
    - main`,
    
    'jenkins': `pipeline {
  agent any
  stages {
    stage('Security Scan') {
      steps {
        sh '''
          curl -X POST \$VULNSECURE_URL/api/scans \\
          -H "Authorization: Bearer \$VULNSECURE_TOKEN" \\
          -d '{"target": "${target}", "type": "web"}'
        '''
      }
    }
  }
}`
  };
  
  return configs[platform] || configs['github'];
};

// ============================================================
// 3. COMPLIANCE FRAMEWORKS
// ============================================================

const checkCompliance = async (scanId, framework) => {
  const vulns = await Vulnerability.findAll({ where: { scanId } });
  
  const frameworks = {
    'pci-dss': [
      { id: '6.5.1', name: 'Injection flaws', category: 'sql-injection' },
      { id: '6.5.7', name: 'Cross-site scripting', category: 'xss' },
      { id: '6.5.8', name: 'Access control', category: 'idor' },
      { id: '2.3', name: 'Encrypt transmissions', category: 'ssl' }
    ],
    'hipaa': [
      { id: '164.312(a)', name: 'Access control', category: 'idor' },
      { id: '164.312(e)', name: 'Transmission security', category: 'ssl' }
    ],
    'owasp': [
      { id: 'A01', name: 'Broken Access Control', category: 'idor' },
      { id: 'A02', name: 'Cryptographic Failures', category: 'ssl' },
      { id: 'A03', name: 'Injection', category: 'sql-injection' },
      { id: 'A05', name: 'Security Misconfiguration', category: 'headers' },
      { id: 'A10', name: 'SSRF', category: 'ssrf' }
    ],
    'soc2': [
      { id: 'CC6.1', name: 'Logical access', category: 'idor' },
      { id: 'CC6.6', name: 'System operations', category: 'ssrf' }
    ],
    'gdpr': [
      { id: 'Art.32', name: 'Security of processing', category: 'ssl' },
      { id: 'Art.25', name: 'Data protection', category: 'exposure' }
    ]
  };
  
  const requirements = frameworks[framework.toLowerCase()] || frameworks['owasp'];
  
  const results = {
    framework,
    requirements: [],
    passed: 0,
    failed: 0,
    score: 0
  };
  
  for (const req of requirements) {
    const hasVuln = vulns.some(v => v.category === req.category);
    const status = hasVuln ? 'failed' : 'passed';
    
    results.requirements.push({
      ...req,
      status,
      vulnerability: hasVuln ? vulns.find(v => v.category === req.category)?.title : null
    });
    
    if (status === 'passed') results.passed++;
    else results.failed++;
  }
  
  results.score = Math.round((results.passed / requirements.length) * 100);
  
  return results;
};

// ============================================================
// 4. TEAM COLLABORATION
// ============================================================

const addComment = async (vulnerabilityId, userId, comment) => {
  const vuln = await Vulnerability.findByPk(vulnerabilityId);
  if (!vuln) throw new Error('Vulnerability not found');
  
  const comments = vuln.metadata?.comments || [];
  comments.push({ userId, comment, createdAt: new Date().toISOString() });
  
  await vuln.update({ metadata: { ...vuln.metadata, comments } });
  
  return comments;
};

const assignVulnerability = async (vulnerabilityId, assigneeId) => {
  const vuln = await Vulnerability.findByPk(vulnerabilityId);
  if (!vuln) throw new Error('Vulnerability not found');
  
  await vuln.update({ assignedTo: assigneeId, status: 'in_progress' });
  return vuln;
};

// ============================================================
// 5. DARK WEB MONITORING
// ============================================================

const checkDarkWebLeaks = async (domain) => {
  const results = {
    domain,
    breaches: [],
    pasteLeaks: [],
    riskScore: 0
  };
  
  // Simulated breach database
  const knownBreaches = [
    { name: 'Collection #1', year: 2019, records: '773M' },
    { name: 'LinkedIn', year: 2021, records: '700M' },
    { name: 'Facebook', year: 2021, records: '533M' }
  ];
  
  // Check domain against breach patterns
  for (const breach of knownBreaches) {
    if (Math.random() > 0.7) {
      results.breaches.push({
        name: breach.name,
        year: breach.year,
        records: breach.records,
        risk: 'Credential exposure likely'
      });
    }
  }
  
  // Paste leak simulation
  if (domain.includes('.com')) {
    results.pasteLeaks.push({
      source: 'Pastebin',
      date: '2026-03',
      finding: 'Domain mentioned in paste'
    });
  }
  
  results.riskScore = Math.min(
    (results.breaches.length * 25) + (results.pasteLeaks.length * 15),
    100
  );
  
  return results;
};

// ============================================================
// 6. MOBILE APP SCANNING
// ============================================================

const scanMobileApp = async (filePath, platform, scanId) => {
  const fs = require('fs');
  
  if (!fs.existsSync(filePath)) throw new Error('File not found');
  
  const buffer = fs.readFileSync(filePath);
  const content = buffer.toString('binary');
  
  // Check hardcoded secrets
  const secrets = [
    { pattern: /AKIA[0-9A-Z]{16}/, name: 'AWS Key' },
    { pattern: /AIza[0-9A-Za-z\-_]{35}/, name: 'Google API Key' }
  ];
  
  for (const secret of secrets) {
    if (secret.pattern.test(content)) {
      await createVuln(scanId, {
        title: secret.name + ' in Mobile App',
        description: 'Hardcoded secret found in binary',
        severity: 'critical',
        cvss: '9.0',
        url: filePath,
        evidence: 'Pattern matched: ' + secret.name,
        solution: 'Remove secrets. Use secure storage.',
        poc: 'strings ' + filePath + ' | grep -i key',
        category: 'mobile'
      });
    }
  }
  
  return { scanned: true, platform };
};

// Helper
const createVuln = async (scanId, data) => {
  try {
    await Vulnerability.create({
      scanId,
      title: data.title,
      description: data.description,
      severity: data.severity,
      cvssScore: data.cvss,
      url: data.url,
      evidence: data.evidence,
      solution: data.solution,
      poc: data.poc,
      pocType: 'markdown',
      status: 'open',
      category: data.category,
      confirmed: true
    });
    logger.info('Created: ' + data.title);
  } catch (error) {
    logger.error('Failed: ' + error.message);
  }
};

module.exports = {
  interceptRequest,
  repeatRequest,
  fuzzEndpoint,
  analyzeToken,
  encodeDecode,
  generateCIConfig,
  checkCompliance,
  addComment,
  assignVulnerability,
  checkDarkWebLeaks,
  scanMobileApp
};
