const axios = require('axios');
const { Vulnerability, Scan, Asset, User } = require('../models');
const { logger } = require('../utils/logger');

// ============================================================
// 1. AUTHENTICATED SCANNING
// ============================================================

const performAuthenticatedScan = async (targetUrl, scanId, credentials) => {
  logger.info('Starting authenticated scan: ' + targetUrl);
  
  let sessionCookies = '';
  
  // Login
  try {
    const loginResp = await axios.post(
      targetUrl.replace(/\/$/, '') + credentials.loginUrl,
      {
        username: credentials.username,
        password: credentials.password
      },
      { timeout: 10000, validateStatus: () => true }
    );
    
    const cookies = loginResp.headers['set-cookie'];
    if (cookies) {
      sessionCookies = cookies.map(c => c.split(';')[0]).join('; ');
    }
  } catch (e) {
    throw new Error('Authentication failed: ' + e.message);
  }
  
  const headers = { 'Cookie': sessionCookies, 'User-Agent': 'vulNSecure/1.0' };
  
  // Test authenticated endpoints
  const protectedPaths = ['/profile', '/account', '/settings', '/admin', '/dashboard', '/api/me'];
  
  for (const path of protectedPaths) {
    try {
      const resp = await axios.get(targetUrl.replace(/\/$/, '') + path, {
        headers, timeout: 5000, validateStatus: () => true
      });
      
      if (resp.status === 200) {
        // Test for IDOR
        await testIDOR(targetUrl, path, headers, scanId);
        
        // Test for privilege escalation
        await testPrivilegeEscalation(targetUrl, path, headers, scanId);
        
        // Test session security
        await testSessionSecurity(resp, scanId);
      }
    } catch (e) {}
  }
};

const testIDOR = async (url, path, headers, scanId) => {
  const testIds = ['1', '2', '0', '999999'];
  
  for (const id of testIds) {
    try {
      const testUrl = url.replace(/\/$/, '') + path + '?id=' + id;
      const resp = await axios.get(testUrl, { headers, timeout: 5000, validateStatus: () => true });
      
      if (resp.status === 200) {
        await createVuln(scanId, {
          title: 'Insecure Direct Object Reference (IDOR)',
          description: 'Access to other users data via ID manipulation',
          severity: 'high',
          cvss: '7.5',
          cwe: 'CWE-639',
          url: testUrl,
          evidence: 'Accessed data with ID: ' + id,
          solution: 'Implement proper authorization checks',
          poc: 'Test with different IDs: ' + testUrl,
          category: 'idor'
        });
        break;
      }
    } catch (e) {}
  }
};

const testPrivilegeEscalation = async (url, path, headers, scanId) => {
  const adminPaths = ['/admin', '/users', '/manage'];
  
  for (const adminPath of adminPaths) {
    try {
      const resp = await axios.get(url.replace(/\/$/, '') + adminPath, {
        headers, timeout: 5000, validateStatus: () => true
      });
      
      if (resp.status === 200 && !path.includes('admin')) {
        await createVuln(scanId, {
          title: 'Privilege Escalation',
          description: 'Regular user can access admin endpoints',
          severity: 'critical',
          cvss: '9.1',
          cwe: 'CWE-269',
          url: url.replace(/\/$/, '') + adminPath,
          evidence: 'Admin endpoint accessible with user credentials',
          solution: 'Implement role-based access control',
          poc: 'Access ' + adminPath + ' with regular user session',
          category: 'privilege-escalation'
        });
      }
    } catch (e) {}
  }
};

const testSessionSecurity = async (response, scanId) => {
  const cookies = response.headers['set-cookie'] || [];
  
  for (const cookie of cookies) {
    if (!cookie.includes('HttpOnly')) {
      await createVuln(scanId, {
        title: 'Cookie Missing HttpOnly Flag',
        description: 'Session cookie accessible via JavaScript',
        severity: 'medium',
        cvss: '5.4',
        cwe: 'CWE-1004',
        url: response.config.url,
        evidence: 'Cookie: ' + cookie.split(';')[0],
        solution: 'Add HttpOnly flag to session cookies',
        poc: 'document.cookie will show session token',
        category: 'session'
      });
    }
    if (!cookie.includes('Secure')) {
      await createVuln(scanId, {
        title: 'Cookie Missing Secure Flag',
        description: 'Cookie sent over unencrypted HTTP',
        severity: 'medium',
        cvss: '5.4',
        cwe: 'CWE-614',
        url: response.config.url,
        evidence: 'Cookie: ' + cookie.split(';')[0],
        solution: 'Add Secure flag to cookies',
        poc: 'Cookie transmitted over HTTP',
        category: 'session'
      });
    }
  }
};

// ============================================================
// 2. GRAPHQL SECURITY TESTING
// ============================================================

const testGraphQL = async (url, scanId) => {
  logger.info('Testing GraphQL security on: ' + url);
  
  const graphqlPaths = ['/graphql', '/api/graphql', '/query', '/api/query'];
  const baseUrl = url.replace(/\/$/, '');
  
  for (const path of graphqlPaths) {
    try {
      const graphqlUrl = baseUrl + path;
      
      // Test introspection
      const introspectionQuery = {
        query: `{ __schema { types { name fields { name } } } }`
      };
      
      const resp = await axios.post(graphqlUrl, introspectionQuery, {
        headers: { 'Content-Type': 'application/json' },
        timeout: 5000,
        validateStatus: () => true
      });
      
      if (resp.status === 200 && resp.data?.data?.__schema) {
        await createVuln(scanId, {
          title: 'GraphQL Introspection Enabled',
          description: 'GraphQL schema is publicly exposed via introspection',
          severity: 'medium',
          cvss: '5.3',
          cwe: 'CWE-200',
          url: graphqlUrl,
          evidence: 'Schema types: ' + resp.data.data.__schema.types.slice(0, 5).map(t => t.name).join(', '),
          solution: 'Disable introspection in production',
          poc: 'Query: { __schema { types { name } } }',
          category: 'graphql'
        });
      }
      
      // Test depth limit
      const deepQuery = {
        query: `{ user { friends { friends { friends { friends { name } } } } } }`
      };
      
      const depthResp = await axios.post(graphqlUrl, deepQuery, {
        headers: { 'Content-Type': 'application/json' },
        timeout: 5000,
        validateStatus: () => true
      });
      
      if (depthResp.status === 200 && !depthResp.data?.errors?.[0]?.message?.includes('depth')) {
        await createVuln(scanId, {
          title: 'GraphQL Missing Depth Limit',
          description: 'No query depth limit, vulnerable to DoS attacks',
          severity: 'medium',
          cvss: '5.3',
          cwe: 'CWE-770',
          url: graphqlUrl,
          evidence: 'Deep query accepted',
          solution: 'Implement query depth limiting',
          poc: 'Query with nested friends { friends { ... } }',
          category: 'graphql'
        });
      }
      
      // Test batch queries
      const batchQuery = [
        { query: '{ user { name } }' },
        { query: '{ user { email } }' },
        { query: '{ user { password } }' }
      ];
      
      const batchResp = await axios.post(graphqlUrl, batchQuery, {
        headers: { 'Content-Type': 'application/json' },
        timeout: 5000,
        validateStatus: () => true
      });
      
      if (batchResp.status === 200) {
        await createVuln(scanId, {
          title: 'GraphQL Batch Queries Allowed',
          description: 'Batch queries can bypass rate limiting',
          severity: 'low',
          cvss: '3.7',
          cwe: 'CWE-770',
          url: graphqlUrl,
          evidence: 'Batch query accepted',
          solution: 'Disable batch queries or implement per-batch rate limiting',
          poc: 'Send array of queries in single request',
          category: 'graphql'
        });
      }
      
    } catch (e) {}
  }
};

// ============================================================
// 3. CLOUD SECURITY (S3 BUCKETS)
// ============================================================

const testCloudSecurity = async (url, scanId) => {
  logger.info('Testing cloud security: ' + url);
  
  // Extract potential bucket names
  const hostname = url.replace(/^(https?:\/\/)?/, '').split('/')[0];
  const bucketNames = [
    hostname,
    hostname.replace(/\./g, '-'),
    hostname.replace(/\./g, ''),
    hostname.split('.')[0]
  ];
  
  // Test AWS S3
  for (const bucket of bucketNames) {
    try {
      const s3Url = `https://${bucket}.s3.amazonaws.com`;
      const resp = await axios.get(s3Url, { timeout: 5000, validateStatus: () => true });
      
      if (resp.status === 200) {
        await createVuln(scanId, {
          title: 'Public S3 Bucket Found',
          description: 'AWS S3 bucket is publicly accessible',
          severity: 'critical',
          cvss: '9.1',
          cwe: 'CWE-732',
          url: s3Url,
          evidence: 'Bucket accessible',
          solution: 'Restrict bucket permissions',
          poc: 'curl ' + s3Url,
          category: 'cloud'
        });
      }
    } catch (e) {}
    
    // Test with different regions
    const regions = ['us-east-1', 'us-west-2', 'eu-west-1'];
    for (const region of regions) {
      try {
        const s3Url = `https://${bucket}.s3.${region}.amazonaws.com`;
        const resp = await axios.get(s3Url, { timeout: 5000, validateStatus: () => true });
        
        if (resp.status === 200) {
          await createVuln(scanId, {
            title: 'Public S3 Bucket (' + region + ')',
            description: 'AWS S3 bucket publicly accessible in region ' + region,
            severity: 'critical',
            cvss: '9.1',
            cwe: 'CWE-732',
            url: s3Url,
            evidence: 'Bucket accessible',
            solution: 'Restrict bucket permissions',
            poc: 'curl ' + s3Url,
            category: 'cloud'
          });
        }
      } catch (e) {}
    }
  }
};

// ============================================================
// 4. SLACK/TEAMS/WEBHOOK NOTIFICATIONS
// ============================================================

const sendSlackNotification = async (webhookUrl, vulnerability) => {
  try {
    const severityEmoji = {
      critical: ':rotating_light:',
      high: ':warning:',
      medium: ':exclamation:',
      low: ':information_source:'
    };
    
    const message = {
      blocks: [
        {
          type: 'header',
          text: {
            type: 'plain_text',
            text: (severityEmoji[vulnerability.severity] || '') + ' ' + vulnerability.severity.toUpperCase() + ' Vulnerability Found'
          }
        },
        {
          type: 'section',
          fields: [
            { type: 'mrkdwn', text: '*Title:*\n' + vulnerability.title },
            { type: 'mrkdwn', text: '*CVSS:*\n' + (vulnerability.cvssScore || 'N/A') }
          ]
        },
        {
          type: 'section',
          text: { type: 'mrkdwn', text: '*URL:*\n' + vulnerability.url }
        },
        {
          type: 'section',
          text: { type: 'mrkdwn', text: '*Description:*\n' + vulnerability.description.substring(0, 200) }
        }
      ]
    };
    
    await axios.post(webhookUrl, message, { timeout: 5000 });
    logger.info('Slack notification sent');
    return true;
  } catch (e) {
    logger.error('Slack notification failed: ' + e.message);
    return false;
  }
};

const sendTeamsNotification = async (webhookUrl, vulnerability) => {
  try {
    const card = {
      '@type': 'MessageCard',
      '@context': 'http://schema.org/extensions',
      themeColor: vulnerability.severity === 'critical' ? 'FF0000' : vulnerability.severity === 'high' ? 'FF6600' : 'FFCC00',
      summary: vulnerability.title,
      sections: [{
        activityTitle: vulnerability.severity.toUpperCase() + ': ' + vulnerability.title,
        facts: [
          { name: 'URL', value: vulnerability.url },
          { name: 'CVSS', value: vulnerability.cvssScore || 'N/A' },
          { name: 'Category', value: vulnerability.category || 'N/A' }
        ],
        text: vulnerability.description.substring(0, 300)
      }]
    };
    
    await axios.post(webhookUrl, card, { timeout: 5000 });
    logger.info('Teams notification sent');
    return true;
  } catch (e) {
    logger.error('Teams notification failed: ' + e.message);
    return false;
  }
};

const sendWebhookNotification = async (webhookUrl, data) => {
  try {
    await axios.post(webhookUrl, {
      event: 'vulnerability_found',
      timestamp: new Date().toISOString(),
      data
    }, { timeout: 5000 });
    return true;
  } catch (e) {
    return false;
  }
};

// ============================================================
// 5. ASSET INVENTORY
// ============================================================

const discoverAssets = async (domain, userId) => {
  logger.info('Discovering assets for: ' + domain);
  
  const assets = [];
  const cleanDomain = domain.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];
  
  // Common subdomains
  const subs = ['www', 'mail', 'api', 'admin', 'dev', 'staging', 'test', 'portal', 'login', 'cdn', 'static', 'blog', 'shop', 'app'];
  
  for (const sub of subs) {
    try {
      const subdomain = sub + '.' + cleanDomain;
      const resp = await axios.get('https://' + subdomain, { timeout: 3000, validateStatus: () => true });
      
      if (resp.status < 500) {
        const asset = await Asset.create({
          userId,
          name: subdomain,
          type: 'subdomain',
          url: 'https://' + subdomain,
          status: 'active',
          metadata: {
            httpStatus: resp.status,
            server: resp.headers['server'] || 'unknown'
          }
        });
        assets.push(asset);
      }
    } catch (e) {}
  }
  
  return assets;
};

const calculateAssetRisk = async (assetId) => {
  const asset = await Asset.findByPk(assetId, {
    include: [{ model: Scan, as: 'scans' }]
  });
  
  if (!asset) return 0;
  
  let riskScore = 0;
  
  // Add risk for each vulnerability
  for (const scan of asset.scans || []) {
    const vulns = await Vulnerability.findAll({ where: { scanId: scan.id } });
    for (const vuln of vulns) {
      if (vuln.severity === 'critical') riskScore += 10;
      else if (vuln.severity === 'high') riskScore += 7;
      else if (vuln.severity === 'medium') riskScore += 4;
      else riskScore += 1;
    }
  }
  
  return Math.min(riskScore, 100);
};

// ============================================================
// 6. JWT SECURITY TESTING
// ============================================================

const testJWTSecurity = async (url, scanId) => {
  logger.info('Testing JWT security on: ' + url);
  
  try {
    const resp = await axios.get(url, { timeout: 5000, validateStatus: () => true });
    const authHeader = resp.headers['authorization'] || '';
    
    // Check for JWT in response
    if (authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      const parts = token.split('.');
      
      if (parts.length === 3) {
        // Decode header
        try {
          const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
          
          // Check for 'none' algorithm
          if (header.alg === 'none') {
            await createVuln(scanId, {
              title: 'JWT None Algorithm',
              description: 'JWT uses none algorithm, allowing token forgery',
              severity: 'critical',
              cvss: '9.8',
              cwe: 'CWE-345',
              url: url,
              evidence: 'JWT header: ' + JSON.stringify(header),
              solution: 'Use strong algorithms (RS256, ES256)',
              poc: 'Modify JWT header alg to "none"',
              category: 'jwt'
            });
          }
          
          // Check for weak algorithm
          if (header.alg === 'HS256') {
            await createVuln(scanId, {
              title: 'JWT Uses HS256 (Symmetric)',
              description: 'HS256 is vulnerable if public key is exposed',
              severity: 'medium',
              cvss: '5.3',
              cwe: 'CWE-327',
              url: url,
              evidence: 'JWT uses HS256',
              solution: 'Consider using RS256 or ES256',
              poc: 'Algorithm confusion attack possible',
              category: 'jwt'
            });
          }
        } catch (e) {}
      }
    }
  } catch (e) {}
};

// ============================================================
// 7. DNS SECURITY
// ============================================================

const testDNSSecurity = async (domain, scanId) => {
  logger.info('Testing DNS security for: ' + domain);
  
  const cleanDomain = domain.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];
  
  // Check SPF record
  try {
    const resp = await axios.get(`https://dns.google/resolve?name=${cleanDomain}&type=TXT`, { timeout: 5000 });
    
    const txtRecords = resp.data?.Answer?.map(a => a.data) || [];
    const hasSPF = txtRecords.some(r => r.includes('v=spf1'));
    
    if (!hasSPF) {
      await createVuln(scanId, {
        title: 'Missing SPF Record',
        description: 'No SPF record found, domain vulnerable to email spoofing',
        severity: 'medium',
        cvss: '5.3',
        cwe: 'CWE-940',
        url: cleanDomain,
        evidence: 'No TXT record with v=spf1',
        solution: 'Add SPF record: v=spf1 include:_spf.google.com ~all',
        poc: 'Spoof email from @' + cleanDomain,
        category: 'email-security'
      });
    }
    
    const hasDMARC = txtRecords.some(r => r.includes('v=DMARC1'));
    if (!hasDMARC) {
      await createVuln(scanId, {
        title: 'Missing DMARC Record',
        description: 'No DMARC record, no email authentication policy',
        severity: 'medium',
        cvss: '5.3',
        cwe: 'CWE-940',
        url: '_dmarc.' + cleanDomain,
        evidence: 'No DMARC record found',
        solution: 'Add DMARC record: v=DMARC1; p=reject; rua=mailto:dmarc@domain.com',
        poc: 'Email spoofing not prevented',
        category: 'email-security'
      });
    }
  } catch (e) {}
};

// ============================================================
// 8. SSL/TLS DEEP SCAN
// ============================================================

const testSSLDeep = async (hostname, scanId) => {
  logger.info('SSL deep scan for: ' + hostname);
  
  // Check HTTPS
  try {
    const resp = await axios.get('https://' + hostname, { timeout: 5000, validateStatus: () => true });
    
    // Check HSTS
    if (!resp.headers['strict-transport-security']) {
      await createVuln(scanId, {
        title: 'Missing HSTS Header',
        description: 'No HTTPS enforcement, vulnerable to downgrade attacks',
        severity: 'high',
        cvss: '6.5',
        cwe: 'CWE-319',
        url: 'https://' + hostname,
        evidence: 'No Strict-Transport-Security header',
        solution: 'Add HSTS: max-age=31536000; includeSubDomains',
        poc: 'MITM can downgrade to HTTP',
        category: 'ssl'
      });
    }
    
    // Check HTTP to HTTPS redirect
    const httpResp = await axios.get('http://' + hostname, { timeout: 5000, validateStatus: () => true });
    if (httpResp.status !== 301 && httpResp.status !== 302) {
      await createVuln(scanId, {
        title: 'No HTTP to HTTPS Redirect',
        description: 'HTTP version accessible without redirect',
        severity: 'medium',
        cvss: '5.3',
        cwe: 'CWE-319',
        url: 'http://' + hostname,
        evidence: 'HTTP responds with ' + httpResp.status,
        solution: 'Configure server to redirect HTTP to HTTPS',
        poc: 'http://' + hostname + ' accessible',
        category: 'ssl'
      });
    }
  } catch (e) {}
};

// ============================================================
// 9. WAF DETECTION
// ============================================================

const detectWAF = async (url, scanId) => {
  logger.info('Detecting WAF on: ' + url);
  
  const wafSignatures = {
    'cloudflare': ['cf-ray', 'cloudflare'],
    'akamai': ['akamai', 'x-akamai'],
    'imperva': ['incap_ses', 'x-iinfo'],
    'aws': ['x-amzn', 'x-amz-cf'],
    'sucuri': ['x-sucuri']
  };
  
  try {
    // Send malicious payload to trigger WAF
    const testUrl = url + (url.includes('?') ? '&' : '?') + 'id=1%20OR%201=1';
    const resp = await axios.get(testUrl, { timeout: 5000, validateStatus: () => true });
    
    const headers = resp.headers;
    
    for (const [waf, signatures] of Object.entries(wafSignatures)) {
      for (const sig of signatures) {
        if (Object.keys(headers).some(h => h.toLowerCase().includes(sig)) || 
            JSON.stringify(headers).toLowerCase().includes(sig)) {
          await createVuln(scanId, {
            title: 'WAF Detected: ' + waf.toUpperCase(),
            description: 'Web Application Firewall detected. May block some scans.',
            severity: 'info',
            cvss: '0.0',
            cwe: 'N/A',
            url: url,
            evidence: 'WAF signature: ' + sig,
            solution: 'WAF is present - ensure proper configuration',
            poc: 'WAF may block automated scanners',
            category: 'waf'
          });
          return;
        }
      }
    }
  } catch (e) {}
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
      cveId: data.cwe,
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
  performAuthenticatedScan,
  testGraphQL,
  testCloudSecurity,
  sendSlackNotification,
  sendTeamsNotification,
  sendWebhookNotification,
  discoverAssets,
  calculateAssetRisk,
  testJWTSecurity,
  testDNSSecurity,
  testSSLDeep,
  detectWAF
};
