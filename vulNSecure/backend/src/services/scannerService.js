const axios = require('axios');
const fs = require('fs');
const { Scan, Vulnerability } = require('../models');
const { logger } = require('../utils/logger');

// ============================================================
// MAIN SCANNER
// ============================================================

const performScan = async (target, scanId) => {
  logger.info('Starting scan for: ' + target + ' scanId: ' + scanId);
  
  let url = target;
  if (!url.startsWith('http')) {
    url = 'https://' + url;
  }
  
  try {
    // Verify scan exists
    const scan = await Scan.findByPk(scanId);
    if (!scan) {
      throw new Error('Scan not found');
    }
    
    await updateProgress(scanId, 10);
    
    // Get base response
    let baseResponse;
    try {
      baseResponse = await axios.get(url, { 
        timeout: 10000, 
        validateStatus: () => true 
      });
    } catch (e) {
      throw new Error('Cannot connect to target: ' + e.message);
    }
    
    await updateProgress(scanId, 30);
    
    // Check security headers
    const headers = baseResponse.headers;
    
    // Missing HSTS
    if (!headers['strict-transport-security']) {
      await createVuln(scanId, {
        title: 'Missing HSTS Header',
        description: 'Strict-Transport-Security header not found. This allows MITM attacks.',
        severity: 'high',
        cvss: '6.5',
        url: url,
        evidence: 'Header not found',
        solution: 'Add: Strict-Transport-Security: max-age=31536000',
        poc: 'Test: curl -I ' + url + ' | grep -i strict-transport',
        category: 'headers'
      });
    }
    
    // Missing X-Frame-Options
    if (!headers['x-frame-options']) {
      await createVuln(scanId, {
        title: 'Missing X-Frame-Options Header',
        description: 'X-Frame-Options header not found. Site can be embedded in iframes.',
        severity: 'medium',
        cvss: '5.3',
        url: url,
        evidence: 'Header not found',
        solution: 'Add: X-Frame-Options: DENY',
        poc: 'Test: curl -I ' + url + ' | grep -i x-frame-options',
        category: 'headers'
      });
    }
    
    // Missing CSP
    if (!headers['content-security-policy']) {
      await createVuln(scanId, {
        title: 'Missing Content-Security-Policy',
        description: 'CSP header not found. No XSS protection via CSP.',
        severity: 'medium',
        cvss: '6.1',
        url: url,
        evidence: 'Header not found',
        solution: 'Add: Content-Security-Policy: default-src \'self\'',
        poc: 'Test: curl -I ' + url + ' | grep -i content-security-policy',
        category: 'headers'
      });
    }
    
    await updateProgress(scanId, 50);
    
    // Check CORS
    try {
      const corsResp = await axios.get(url, {
        headers: { 'Origin': 'https://evil.com' },
        timeout: 5000,
        validateStatus: () => true
      });
      
      const acao = corsResp.headers['access-control-allow-origin'];
      if (acao === '*' || acao === 'https://evil.com') {
        await createVuln(scanId, {
          title: 'CORS Misconfiguration',
          description: 'Server allows cross-origin requests from any origin.',
          severity: 'medium',
          cvss: '5.3',
          url: url,
          evidence: 'Access-Control-Allow-Origin: ' + acao,
          solution: 'Restrict CORS to trusted origins only',
          poc: 'Test: curl -H "Origin: https://evil.com" -I ' + url,
          category: 'cors'
        });
      }
    } catch (e) {}
    
    await updateProgress(scanId, 60);
    
    // Check sensitive files
    const sensitiveFiles = [
      { path: '/.env', name: 'Environment File', severity: 'critical' },
      { path: '/.git/config', name: 'Git Config', severity: 'high' },
      { path: '/robots.txt', name: 'Robots.txt', severity: 'info' }
    ];
    
    for (const file of sensitiveFiles) {
      try {
        const fileUrl = url.replace(/\/$/, '') + file.path;
        const resp = await axios.get(fileUrl, { timeout: 3000, validateStatus: () => true });
        
        if (resp.status === 200 && resp.data.length > 10) {
          const content = resp.data.toString();
          const contentType = resp.headers['content-type'] || '';
          
          // Only report if real exposure (not HTML error pages)
          const isHTML = contentType.includes('text/html');
          
          // .env file - must contain actual env variables (KEY=VALUE pattern)
          if (file.path.includes('.env') && !isHTML) {
            const envPatterns = /^[A-Z_]+=.*$/m;
            if (envPatterns.test(content)) {
              await createVuln(scanId, {
                title: file.name + ' Exposed',
                description: 'Environment file (.env) is publicly accessible and contains sensitive configuration like database credentials, API keys, and secrets.',
                severity: 'critical',
                cvss: '9.1',
                url: fileUrl,
                evidence: 'Contains: ' + content.split('\n').slice(0, 3).join(', '),
                solution: 'Delete .env file from web root. Add .env to .gitignore. Use environment variables.',
                poc: 'Test: curl ' + fileUrl + '\n\nExample content:\nDB_HOST=localhost\nDB_PASSWORD=secret123\nAPI_KEY=abc123',
                category: 'exposure'
              });
            }
          }
          
          // .git/config - must contain [core] or [remote]
          if (file.path.includes('.git') && !isHTML && (content.includes('[core]') || content.includes('[remote]'))) {
            await createVuln(scanId, {
              title: file.name + ' Exposed',
              description: 'Git configuration is publicly accessible. Attackers can download entire source code.',
              severity: 'high',
              cvss: '7.5',
              url: fileUrl,
              evidence: 'Git config file accessible',
              solution: 'Delete .git directory from web root. Never deploy .git folder.',
              poc: 'Test: curl ' + fileUrl + '\n\nExploit: git clone ' + url.replace(/\/$/, '') + '/.git',
              category: 'exposure'
            });
          }
        }
      } catch (e) {}
    }
    
    await updateProgress(scanId, 75);
    
    // Check for XSS (basic test)
    const xssPayloads = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>'];
    const params = ['q', 'search', 'name'];
    
    for (const param of params) {
      for (const payload of xssPayloads) {
        try {
          const testUrl = url + (url.includes('?') ? '&' : '?') + param + '=' + encodeURIComponent(payload);
          const resp = await axios.get(testUrl, { timeout: 5000, validateStatus: () => true });
          
          const contentType = resp.headers['content-type'] || '';
          
          // XSS only works in HTML
          if (contentType.includes('text/html')) {
            const content = resp.data.toString();
            
            // Check if payload is reflected unencoded
            if (content.includes(payload)) {
              await createVuln(scanId, {
                title: 'Reflected XSS Vulnerability',
                description: 'Parameter "' + param + '" reflects input unencoded',
                severity: 'high',
                cvss: '6.1',
                url: testUrl,
                evidence: 'Payload reflected in response',
                solution: 'Encode all user output',
                poc: 'Test: Open ' + testUrl + ' in browser. If alert shows, XSS confirmed.',
                category: 'xss'
              });
              break; // Found one, move to next param
            }
          }
        } catch (e) {}
      }
    }
    
    await updateProgress(scanId, 90);
    
    // Check HTTP vs HTTPS
    if (url.startsWith('https://')) {
      try {
        const httpUrl = url.replace('https://', 'http://');
        await axios.get(httpUrl, { timeout: 3000, validateStatus: () => true });
        
        await createVuln(scanId, {
          title: 'HTTP Enabled (No Redirect)',
          description: 'HTTP version accessible without redirect to HTTPS',
          severity: 'low',
          cvss: '3.7',
          url: httpUrl,
          evidence: 'HTTP responds without redirect',
          solution: 'Redirect all HTTP to HTTPS',
          poc: 'Test: curl -I http://' + url.replace('https://', ''),
          category: 'ssl'
        });
      } catch (e) {}
    }
    
    await updateProgress(scanId, 100);
    
    // Get final count
    const vulnCount = await Vulnerability.count({ where: { scanId } });
    logger.info('Scan complete: ' + vulnCount + ' vulnerabilities found');
    
    return vulnCount;
    
  } catch (error) {
    logger.error('Scan failed: ' + error.message);
    throw error;
  }
};

// ============================================================
// BINARY SCANNER
// ============================================================

const performBinaryScan = async (filePath, scanId) => {
  logger.info('Starting binary scan: ' + filePath);
  
  try {
    const scan = await Scan.findByPk(scanId);
    if (!scan) throw new Error('Scan not found');
    
    if (!fs.existsSync(filePath)) {
      throw new Error('File not found');
    }
    
    await updateProgress(scanId, 20);
    
    const buffer = fs.readFileSync(filePath);
    const strings = extractStrings(buffer);
    
    await updateProgress(scanId, 50);
    
    // Check for hardcoded secrets
    const secretPatterns = [
      { pattern: /AKIA[0-9A-Z]{16}/i, name: 'AWS Access Key', severity: 'critical' },
      { pattern: /sk_live_[0-9a-zA-Z]{24,}/i, name: 'Stripe Secret Key', severity: 'critical' },
      { pattern: /ghp_[0-9a-zA-Z]{36}/i, name: 'GitHub Token', severity: 'critical' },
      { pattern: /-----BEGIN (RSA )?PRIVATE KEY-----/, name: 'Private Key', severity: 'critical' },
      { pattern: /password\s*[:=]\s*['"][^'"]{6,}['"]/i, name: 'Hardcoded Password', severity: 'high' }
    ];
    
    for (const { pattern, name, severity } of secretPatterns) {
      for (const str of strings) {
        if (pattern.test(str)) {
          await createVuln(scanId, {
            title: name + ' Found in Binary',
            description: 'Hardcoded secret detected in binary file',
            severity: severity,
            cvss: '9.0',
            url: filePath,
            evidence: 'Secret pattern matched',
            solution: 'Remove hardcoded secrets. Use environment variables.',
            poc: 'Test: strings ' + filePath + ' | grep -i password',
            category: 'secrets'
          });
          break;
        }
      }
    }
    
    await updateProgress(scanId, 80);
    
    // Check for dangerous functions
    const dangerous = [
      { func: 'strcpy', name: 'Buffer Overflow Risk' },
      { func: 'system', name: 'Command Injection Risk' },
      { func: 'eval', name: 'Code Injection Risk' }
    ];
    
    const content = buffer.toString('binary');
    for (const { func, name } of dangerous) {
      if (content.includes(func)) {
        await createVuln(scanId, {
          title: 'Unsafe Function: ' + func,
          description: 'Binary uses dangerous function ' + func,
          severity: 'high',
          cvss: '7.0',
          url: filePath,
          evidence: 'Function ' + func + ' found',
          solution: 'Replace with safe alternative (strncpy, execve, etc.)',
          poc: 'Test: strings ' + filePath + ' | grep ' + func,
          category: 'unsafe'
        });
      }
    }
    
    await updateProgress(scanId, 100);
    
    const vulnCount = await Vulnerability.count({ where: { scanId } });
    logger.info('Binary scan complete: ' + vulnCount + ' issues found');
    
    return vulnCount;
    
  } catch (error) {
    logger.error('Binary scan failed: ' + error.message);
    throw error;
  }
};

// ============================================================
// HELPER FUNCTIONS
// ============================================================

const createVuln = async (scanId, data) => {
  try {
    await Vulnerability.create({
      scanId: scanId,
      title: data.title,
      description: data.description,
      severity: data.severity,
      cvssScore: data.cvss || null,
      url: data.url,
      evidence: data.evidence,
      solution: data.solution,
      status: 'open',
      category: data.category || 'general',
      poc: data.poc || null,
      pocType: data.poc ? 'curl-command' : 'none',
      cveId: null
    });
    logger.info('Created vulnerability: ' + data.title);
  } catch (error) {
    logger.error('Failed to create vulnerability: ' + error.message);
  }
};

const updateProgress = async (scanId, progress) => {
  try {
    await Scan.update({ progress }, { where: { id: scanId } });
  } catch (e) {}
};

const extractStrings = (buffer, minLength = 4) => {
  const strings = [];
  let current = '';
  
  for (let i = 0; i < buffer.length; i++) {
    const byte = buffer[i];
    if (byte >= 32 && byte <= 126) {
      current += String.fromCharCode(byte);
    } else {
      if (current.length >= minLength) strings.push(current);
      current = '';
    }
  }
  
  if (current.length >= minLength) strings.push(current);
  return strings;
};

// Subdomain enumeration
const enumerateSubdomains = async (domain) => {
  const results = { found: [], total: 0 };
  const cleanDomain = domain.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];
  
  const subs = ['www', 'mail', 'api', 'admin', 'dev', 'test', 'staging', 'portal'];
  
  for (const sub of subs) {
    try {
      const subdomain = sub + '.' + cleanDomain;
      await axios.get('https://' + subdomain, { timeout: 3000, validateStatus: () => true });
      results.found.push({ subdomain });
    } catch (e) {}
  }
  
  results.total = results.found.length;
  return results;
};

// Port scanning
const scanPorts = async (hostname) => {
  const results = { openPorts: [], services: [] };
  const ports = [
    { port: 80, service: 'HTTP' },
    { port: 443, service: 'HTTPS' },
    { port: 8080, service: 'HTTP-Alt' }
  ];
  
  for (const { port, service } of ports) {
    try {
      const proto = port === 443 ? 'https' : 'http';
      await axios.get(proto + '://' + hostname + ':' + port, { timeout: 3000, validateStatus: () => true });
      results.openPorts.push(port);
      results.services.push({ port, service });
    } catch (e) {}
  }
  return results;
};

// Technology detection - Comprehensive
const detectTechnologies = async (url) => {
  const techs = [];
  
  try {
    const response = await axios.get(url, { timeout: 10000, validateStatus: () => true });
    const headers = response.headers;
    const content = response.data.toString();
    
    // Server detection from headers
    const server = headers['server'];
    if (server) {
      techs.push({ type: 'server', name: server, version: '' });
    }
    
    // X-Powered-By header
    const powered = headers['x-powered-by'];
    if (powered) {
      techs.push({ type: 'framework', name: powered, version: '' });
    }
    
    // Via header (proxy/CDN)
    const via = headers['via'];
    if (via) {
      techs.push({ type: 'proxy', name: 'Proxy/CDN', version: via });
    }
    
    // Content-Type analysis
    const contentType = headers['content-type'] || '';
    
    // CMS Detection
    const cmsChecks = {
      'WordPress': ['wp-content', 'wp-includes', 'wordpress', '/wp-json/', 'wp-admin'],
      'Joomla': ['joomla', '/components/com_', 'option=com_'],
      'Drupal': ['drupal', '/sites/default/', 'Drupal.settings', '/misc/drupal.js'],
      'Magento': ['magento', 'Mage.Cookies', '/skin/frontend/'],
      'Shopify': ['shopify', 'Shopify.theme', 'cdn.shopify.com'],
      'Wix': ['wix', 'wix.com', 'wix-code'],
      'Squarespace': ['squarespace', 'sqsp-cdn'],
      'Ghost': ['ghost', '/assets/built/']
    };
    
    for (const [cms, patterns] of Object.entries(cmsChecks)) {
      if (patterns.some(p => content.toLowerCase().includes(p.toLowerCase()))) {
        techs.push({ type: 'cms', name: cms, version: '' });
      }
    }
    
    // Frontend Framework Detection
    const frontendChecks = {
      'React': ['react', '_reactRoot', '__REACT_DEVTOOLS', 'react-dom', 'react.production.min'],
      'Vue.js': ['vue', '__vue__', 'Vue.config', 'vue-router'],
      'Angular': ['ng-app', 'ng-controller', 'angular.', '@angular', 'AngularJS'],
      'jQuery': ['jquery', 'jQuery.fn', 'jquery.min'],
      'Svelte': ['svelte', '__svelte'],
      'Next.js': ['__NEXT_DATA__', '_next/static', 'next.js'],
      'Nuxt.js': ['__NUXT__', '_nuxt/'],
      'Bootstrap': ['bootstrap', 'btn-primary', 'navbar-brand']
    };
    
    for (const [framework, patterns] of Object.entries(frontendChecks)) {
      if (patterns.some(p => content.toLowerCase().includes(p.toLowerCase()))) {
        techs.push({ type: 'frontend', name: framework, version: '' });
      }
    }
    
    // Backend Language Detection
    const langChecks = {
      'PHP': ['.php', 'PHPSESSID', 'phpversion()', 'X-Powered-By: PHP'],
      'ASP.NET': ['.aspx', 'ASP.NET', '__VIEWSTATE', 'ASP.NET_SessionId', 'asp.net'],
      'Java': ['jsessionid', 'JSESSIONID', '.jsp', 'java.'],
      'Python': ['django', 'flask', 'python', 'werkzeug', 'WSGIServer'],
      'Ruby': ['ruby', 'rails', 'phusion', 'passenger'],
      'Node.js': ['express', 'connect.sid', 'X-Powered-By: Express'],
      'Go': ['Go-http-client'],
      'Rust': ['actix-web', 'rocket']
    };
    
    for (const [lang, patterns] of Object.entries(langChecks)) {
      if (patterns.some(p => 
        content.toLowerCase().includes(p.toLowerCase()) || 
        JSON.stringify(headers).toLowerCase().includes(p.toLowerCase())
      )) {
        techs.push({ type: 'language', name: lang, version: '' });
      }
    }
    
    // CDN Detection
    const cdnChecks = {
      'Cloudflare': ['cf-ray', 'cloudflare', '__cfduid'],
      'CloudFront': ['x-amz-cf-id', 'cloudfront'],
      'Akamai': ['akamai', 'x-akamai'],
      'Fastly': ['fastly', 'x-fastly'],
      'Vercel': ['x-vercel-', 'vercel'],
      'Netlify': ['x-nf-', 'netlify'],
      'GitHub Pages': ['github-pages', 'x-github-request-id']
    };
    
    for (const [cdn, patterns] of Object.entries(cdnChecks)) {
      if (patterns.some(p => JSON.stringify(headers).toLowerCase().includes(p.toLowerCase()))) {
        techs.push({ type: 'cdn', name: cdn, version: '' });
      }
    }
    
    // Analytics/Tracking Detection
    const analyticsChecks = {
      'Google Analytics': ['google-analytics', 'gtag', 'UA-', 'G-'],
      'Google Tag Manager': ['googletagmanager', 'GTM-'],
      'Facebook Pixel': ['fbevents', 'fbq(', 'facebook.com/tr'],
      'Hotjar': ['hotjar', '_hjSettings'],
      'Mixpanel': ['mixpanel', 'mixpanel.'],
      'Segment': ['analytics.js', 'segment']
    };
    
    for (const [analytics, patterns] of Object.entries(analyticsChecks)) {
      if (patterns.some(p => content.toLowerCase().includes(p.toLowerCase()))) {
        techs.push({ type: 'analytics', name: analytics, version: '' });
      }
    }
    
    // API/Backend Detection
    const apiChecks = {
      'GraphQL': ['graphql', '/graphql', '__schema'],
      'REST API': ['api/v', '/api/', 'application/json'],
      'Swagger': ['swagger', 'openapi', 'api-docs'],
      'gRPC': ['grpc']
    };
    
    for (const [api, patterns] of Object.entries(apiChecks)) {
      if (patterns.some(p => content.toLowerCase().includes(p.toLowerCase()))) {
        techs.push({ type: 'api', name: api, version: '' });
      }
    }
    
    // Database hints from error messages
    const dbChecks = {
      'MySQL': ['mysql', 'mysqli'],
      'PostgreSQL': ['postgresql', 'pg_'],
      'MongoDB': ['mongodb', 'mongo'],
      'Redis': ['redis', 'redis-server'],
      'SQLite': ['sqlite'],
      'Oracle': ['ora-', 'oracle'],
      'MSSQL': ['sql server', 'mssql']
    };
    
    for (const [db, patterns] of Object.entries(dbChecks)) {
      if (patterns.some(p => content.toLowerCase().includes(p.toLowerCase()))) {
        techs.push({ type: 'database', name: db, version: '' });
      }
    }
    
    // Security headers analysis
    const securityHeaders = {
      'HSTS': headers['strict-transport-security'],
      'CSP': headers['content-security-policy'],
      'X-Frame-Options': headers['x-frame-options'],
      'X-Content-Type-Options': headers['x-content-type-options']
    };
    
    for (const [header, value] of Object.entries(securityHeaders)) {
      if (value) {
        techs.push({ type: 'security', name: header, version: value });
      }
    }
    
  } catch (e) {
    logger.error('Technology detection failed: ' + e.message);
  }
  
  // Remove duplicates
  const unique = [];
  const seen = new Set();
  for (const tech of techs) {
    const key = tech.type + ':' + tech.name;
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(tech);
    }
  }
  
  return unique;
};

module.exports = { 
  performScan, 
  performBinaryScan,
  enumerateSubdomains,
  scanPorts,
  detectTechnologies
};
