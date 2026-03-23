const axios = require('axios');

async function runTests() {
  console.log('═══════════════════════════════════════════════════════════════════');
  console.log('              VULNSECURE - QA TEST REPORT');
  console.log('═══════════════════════════════════════════════════════════════════');
  
  const results = { passed: [], failed: [] };
  
  const test = async (category, name, fn) => {
    try {
      await fn();
      console.log('[PASS] ' + category + ': ' + name);
      results.passed.push({ category, name });
    } catch (e) {
      console.log('[FAIL] ' + category + ': ' + name + ' - ' + (e.message || 'Unknown error'));
      results.failed.push({ category, name, error: e.message });
    }
  };
  
  // Get token
  let token = '';
  try {
    const regResp = await axios.post('http://localhost:5001/api/auth/register', {
      username: 'qatest', email: 'admin@vulnsecure.com', password: 'admin123',
      firstName: 'QA', lastName: 'Test'
    }).catch(() => {});
    
    const loginResp = await axios.post('http://localhost:5001/api/auth/login', {
      email: 'admin@vulnsecure.com', password: 'admin123'
    });
    token = loginResp.data.data.token;
    console.log('[PASS] Auth: Login successful\n');
  } catch (e) {
    console.log('[FAIL] Auth: Login failed - ' + e.message);
    return;
  }
  
  const headers = { Authorization: 'Bearer ' + token };
  
  // 1. Auth Tests
  console.log('1. AUTHENTICATION');
  console.log('─'.repeat(50));
  await test('Auth', 'Get Current User', async () => {
    const resp = await axios.get('http://localhost:5001/api/auth/me', { headers });
    if (!resp.data.data.user) throw new Error('No user data');
  });
  
  // 2. Scan Tests
  console.log('\n2. SCANNING');
  console.log('─'.repeat(50));
  let scanId = '';
  await test('Scan', 'Create Scan', async () => {
    const resp = await axios.post('http://localhost:5001/api/scans', {
      name: 'QA Scan', target: 'https://httpbin.org', type: 'web'
    }, { headers });
    scanId = resp.data.data.scan.id;
    if (!scanId) throw new Error('No scan ID');
  });
  
  await test('Scan', 'List Scans', async () => {
    const resp = await axios.get('http://localhost:5001/api/scans', { headers });
    if (!resp.data.success) throw new Error('Failed');
  });
  
  await test('Scan', 'Get Scan Details', async () => {
    const resp = await axios.get('http://localhost:5001/api/scans/' + scanId, { headers });
    if (!resp.data.data.scan) throw new Error('No scan data');
  });
  
  // Wait for scan
  console.log('      Waiting for scan to complete...');
  for (let i = 0; i < 20; i++) {
    await new Promise(r => setTimeout(r, 2000));
    const resp = await axios.get('http://localhost:5001/api/scans/' + scanId, { headers });
    if (resp.data.data.scan.status === 'completed') {
      await test('Scan', 'Scan Completed', async () => {});
      break;
    }
    if (resp.data.data.scan.status === 'failed') {
      await test('Scan', 'Scan Completed', async () => { throw new Error('Scan failed'); });
      break;
    }
  }
  
  // 3. Vulnerability Tests
  console.log('\n3. VULNERABILITIES');
  console.log('─'.repeat(50));
  await test('Vulns', 'List Vulnerabilities', async () => {
    const resp = await axios.get('http://localhost:5001/api/vulnerabilities?limit=20', { headers });
    if (!resp.data.success) throw new Error('Failed');
  });
  
  // 4. Recon Tests
  console.log('\n4. RECONNAISSANCE');
  console.log('─'.repeat(50));
  await test('Recon', 'Subdomain Enumeration', async () => {
    const resp = await axios.post('http://localhost:5001/api/pro/subdomains',
      { domain: 'httpbin.org' }, { headers });
    if (!resp.data.success) throw new Error('Failed');
  });
  
  await test('Recon', 'Port Scanning', async () => {
    const resp = await axios.post('http://localhost:5001/api/pro/ports',
      { hostname: 'httpbin.org' }, { headers });
    if (!resp.data.success) throw new Error('Failed');
  });
  
  await test('Recon', 'DNS Enumeration', async () => {
    const resp = await axios.post('http://localhost:5001/api/pro/dns',
      { domain: 'httpbin.org' }, { headers });
    if (!resp.data.success) throw new Error('Failed');
  });
  
  await test('Recon', 'Technology Detection', async () => {
    const resp = await axios.post('http://localhost:5001/api/pro/technologies',
      { url: 'https://httpbin.org' }, { headers });
    if (!resp.data.success) throw new Error('Failed');
  });
  
  await test('Recon', 'SSL Analysis', async () => {
    const resp = await axios.post('http://localhost:5001/api/pro/ssl',
      { hostname: 'httpbin.org' }, { headers });
    if (!resp.data.success) throw new Error('Failed');
  });
  
  // 5. Threat Intelligence Tests
  console.log('\n5. THREAT INTELLIGENCE');
  console.log('─'.repeat(50));
  await test('Threat', 'Threat Intelligence', async () => {
    const resp = await axios.post('http://localhost:5001/api/advanced/threat-intel',
      { domain: 'httpbin.org' }, { headers });
    if (!resp.data.success) throw new Error('Failed');
  });
  
  await test('Threat', 'Dark Web Monitor', async () => {
    const resp = await axios.post('http://localhost:5001/api/complete/darkweb',
      { domain: 'httpbin.org' }, { headers });
    if (!resp.data.success) throw new Error('Failed');
  });
  
  // 6. Compliance Tests
  console.log('\n6. COMPLIANCE');
  console.log('─'.repeat(50));
  const frameworks = ['owasp', 'pci-dss', 'hipaa', 'soc2', 'gdpr'];
  for (const fw of frameworks) {
    await test('Compliance', fw.toUpperCase(), async () => {
      const resp = await axios.post('http://localhost:5001/api/complete/compliance',
        { scanId, framework: fw }, { headers });
      if (!resp.data.success) throw new Error('Failed');
    });
  }
  
  // 7. CI/CD Tests
  console.log('\n7. CI/CD');
  console.log('─'.repeat(50));
  for (const platform of ['github', 'gitlab', 'jenkins']) {
    await test('CI/CD', platform.toUpperCase(), async () => {
      const resp = await axios.post('http://localhost:5001/api/complete/cicd/config',
        { platform, target: 'https://example.com' }, { headers });
      if (!resp.data.success) throw new Error('Failed');
    });
  }
  
  // 8. Attack Surface Tests
  console.log('\n8. ATTACK SURFACE');
  console.log('─'.repeat(50));
  await test('Surface', 'Attack Surface Mapping', async () => {
    const resp = await axios.post('http://localhost:5001/api/advanced/attack-surface',
      { domain: 'httpbin.org' }, { headers });
    if (!resp.data.success) throw new Error('Failed');
  });
  
  // 9. ML Tests
  console.log('\n9. ML DETECTION');
  console.log('─'.repeat(50));
  await test('ML', 'ML Detection', async () => {
    const resp = await axios.post('http://localhost:5001/api/advanced/ml-detect',
      { url: 'https://httpbin.org' }, { headers });
    if (!resp.data.success) throw new Error('Failed');
  });
  
  // 10. Pentest Tests
  console.log('\n10. PENTEST WORKFLOW');
  console.log('─'.repeat(50));
  await test('Pentest', 'Penetration Test', async () => {
    const resp = await axios.post('http://localhost:5001/api/advanced/pentest',
      { target: 'https://httpbin.org' }, { headers });
    if (!resp.data.success) throw new Error('Failed');
  });
  
  // 11. Burp Suite Tests
  console.log('\n11. BURP SUITE');
  console.log('─'.repeat(50));
  await test('Burp', 'Request Interceptor', async () => {
    const resp = await axios.post('http://localhost:5001/api/complete/intercept',
      { url: 'https://httpbin.org/get', method: 'GET' }, { headers });
    if (!resp.data.success) throw new Error('Failed');
  });
  
  await test('Burp', 'Decoder', async () => {
    const resp = await axios.post('http://localhost:5001/api/complete/decode',
      { input: 'hello', type: 'base64-encode' }, { headers });
    if (!resp.data.success) throw new Error('Failed');
  });
  
  // 12. Reports Tests
  console.log('\n12. REPORTS');
  console.log('─'.repeat(50));
  await test('Reports', 'List Reports', async () => {
    const resp = await axios.get('http://localhost:5001/api/reports', { headers });
    if (!resp.data.success) throw new Error('Failed');
  });
  
  await test('Reports', 'Generate Report', async () => {
    const resp = await axios.post('http://localhost:5001/api/reports',
      { title: 'QA Report', type: 'scan', format: 'json' }, { headers });
    if (!resp.data.success) throw new Error('Failed');
  });
  
  // 13. Binary Tests
  console.log('\n13. BINARY ANALYSIS');
  console.log('─'.repeat(50));
  await test('Binary', 'List Binary Scans', async () => {
    const resp = await axios.get('http://localhost:5001/api/scans?type=binary', { headers });
    if (!resp.data.success) throw new Error('Failed');
  });
  
  // SUMMARY
  console.log('\n═══════════════════════════════════════════════════════════════════');
  console.log('                        SUMMARY');
  console.log('═══════════════════════════════════════════════════════════════════');
  console.log('Total Tests: ' + (results.passed.length + results.failed.length));
  console.log('Passed: ' + results.passed.length);
  console.log('Failed: ' + results.failed.length);
  console.log('Success Rate: ' + Math.round((results.passed.length / (results.passed.length + results.failed.length)) * 100) + '%');
  
  if (results.failed.length > 0) {
    console.log('\nFailed Tests:');
    results.failed.forEach(f => console.log('  - ' + f.category + ': ' + f.name));
  }
  
  console.log('\n═══════════════════════════════════════════════════════════════════');
}

runTests().catch(console.error);
