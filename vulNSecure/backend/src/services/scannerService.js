const { exec } = require('child_process');
const { promisify } = require('util');
const { Scan, Vulnerability } = require('../models');
const { logger } = require('../utils/logger');

const execAsync = promisify(exec);

// Nmap scanner service
const runNmapScan = async (scanId, target, configuration = {}) => {
  try {
    const scan = await Scan.findByPk(scanId);
    if (!scan) {
      throw new Error('Scan not found');
    }

    await scan.update({ 
      status: 'running',
      startTime: new Date(),
      progress: 0
    });

    logger.info('Starting Nmap scan', { scanId, target });

    // Build nmap command
    const nmapPath = process.env.NMAP_PATH || '/usr/bin/nmap';
    const scanType = configuration.scanType || 'syn';
    const ports = configuration.ports || '1-1000';
    const timing = configuration.timing || 'T4';
    const scripts = configuration.scripts || 'default';

    let command = `${nmapPath} -s${scanType} -p${ports} -${timing}`;
    
    if (scripts !== 'default') {
      command += ` --script=${scripts}`;
    }

    command += ` --script-timeout=30s --max-retries=2`;
    command += ` -oX - ${target}`;

    logger.info('Executing Nmap command', { command });

    let stdout, stderr;
    let vulnerabilities = [];

    try {
      const result = await execAsync(command, { 
        timeout: configuration.timeout || 300000 // 5 minutes default
      });
      stdout = result.stdout;
      stderr = result.stderr;

      if (stderr && !stderr.includes('Note: Host seems down')) {
        logger.warn('Nmap stderr', { stderr });
      }

      // Parse XML output and extract vulnerabilities
      vulnerabilities = await parseNmapOutput(stdout, scanId);
    } catch (error) {
      // If nmap is not installed or command fails, use mock data in development
      if (process.env.NODE_ENV === 'development' && (error.message.includes('No such file') || error.code === 'ENOENT')) {
        logger.warn('Nmap not found, using mock scan results for development', { scanId, target });
        vulnerabilities = await generateMockScanResults(scanId, target);
        stdout = 'Mock scan output - nmap not installed';
      } else {
        throw error;
      }
    }
    
    // Update scan with results
    await scan.update({
      status: 'completed',
      endTime: new Date(),
      progress: 100,
      results: {
        command,
        output: stdout,
        vulnerabilitiesFound: vulnerabilities.length
      },
      summary: {
        totalHosts: 1,
        openPorts: vulnerabilities.filter(v => v.port).length,
        vulnerabilities: vulnerabilities.length,
        severityBreakdown: {
          critical: vulnerabilities.filter(v => v.severity === 'critical').length,
          high: vulnerabilities.filter(v => v.severity === 'high').length,
          medium: vulnerabilities.filter(v => v.severity === 'medium').length,
          low: vulnerabilities.filter(v => v.severity === 'low').length
        }
      }
    });

    logger.info('Nmap scan completed', { 
      scanId, 
      vulnerabilitiesFound: vulnerabilities.length 
    });

  } catch (error) {
    logger.error('Nmap scan failed', { scanId, error: error.message });
    
    const scan = await Scan.findByPk(scanId);
    if (scan) {
      await scan.update({
        status: 'failed',
        endTime: new Date(),
        errorMessage: error.message
      });
    }
    
    throw error;
  }
};

// Parse Nmap XML output
const parseNmapOutput = async (xmlOutput, scanId) => {
  const vulnerabilities = [];
  
  try {
    // Simple XML parsing for demonstration
    // In production, use proper XML parser like xml2js
    
    const portMatches = xmlOutput.match(/<port protocol="([^"]+)" portid="([^"]+)">[\s\S]*?<state state="open"[\s\S]*?<\/port>/g);
    
    if (portMatches) {
      for (const portMatch of portMatches) {
        const protocolMatch = portMatch.match(/protocol="([^"]+)"/);
        const portMatch2 = portMatch.match(/portid="([^"]+)"/);
        const serviceMatch = portMatch.match(/<service name="([^"]+)"[\s\S]*?version="([^"]+)"/);
        
        if (protocolMatch && portMatch2) {
          const protocol = protocolMatch[1];
          const port = parseInt(portMatch2[1]);
          const service = serviceMatch ? serviceMatch[1] : 'unknown';
          const version = serviceMatch ? serviceMatch[2] : '';
          
          // Create vulnerability record
          const vulnerability = await Vulnerability.create({
            scanId,
            title: `Open ${service} service on port ${port}`,
            description: `Service ${service}${version ? ` version ${version}` : ''} is running on port ${port}/${protocol}`,
            severity: determineSeverity(port, service),
            port,
            service,
            protocol,
            evidence: `Service detected: ${service}${version ? ` ${version}` : ''}`,
            solution: `Review and secure the ${service} service configuration`
          });
          
          vulnerabilities.push(vulnerability);
        }
      }
    }
    
    // Check for script results (vulnerabilities)
    const scriptMatches = xmlOutput.match(/<script id="([^"]+)"[\s\S]*?<elem>([^<]+)<\/elem>/g);
    
    if (scriptMatches) {
      for (const scriptMatch of scriptMatches) {
        const scriptIdMatch = scriptMatch.match(/id="([^"]+)"/);
        const elemMatch = scriptMatch.match(/<elem>([^<]+)<\/elem>/);
        
        if (scriptIdMatch && elemMatch) {
          const scriptId = scriptIdMatch[1];
          const result = elemMatch[1];
          
          if (isVulnerabilityScript(scriptId)) {
            const vulnerability = await Vulnerability.create({
              scanId,
              title: `Nmap script ${scriptId} detected issue`,
              description: result,
              severity: 'medium',
              evidence: `Script: ${scriptId}, Result: ${result}`,
              solution: 'Review and address the identified security issue'
            });
            
            vulnerabilities.push(vulnerability);
          }
        }
      }
    }
    
  } catch (error) {
    logger.error('Error parsing Nmap output', { error: error.message });
  }
  
  return vulnerabilities;
};

// Determine severity based on port and service
const determineSeverity = (port, service) => {
  const highRiskPorts = [21, 23, 135, 139, 445, 1433, 3389, 5432, 3306];
  const highRiskServices = ['ftp', 'telnet', 'rpc', 'smb', 'mssql', 'rdp', 'postgresql', 'mysql'];
  
  if (highRiskPorts.includes(port) || highRiskServices.includes(service.toLowerCase())) {
    return 'high';
  }
  
  if (port < 1024) {
    return 'medium';
  }
  
  return 'low';
};

// Check if script indicates vulnerability
const isVulnerabilityScript = (scriptId) => {
  const vulnScripts = [
    'vuln', 'exploit', 'malware', 'backdoor', 'trojan',
    'ssh-hostkey', 'ssl-cert', 'ssl-enum-ciphers'
  ];
  
  return vulnScripts.some(vuln => scriptId.toLowerCase().includes(vuln));
};

// Generate mock scan results for development when tools aren't installed
const generateMockScanResults = async (scanId, target) => {
  const vulnerabilities = [];
  
  // Simulate scanning delay
  await new Promise(resolve => setTimeout(resolve, 2000));
  
  // Generate mock open ports and services
  const mockPorts = [
    { port: 80, service: 'http', protocol: 'tcp', severity: 'medium' },
    { port: 443, service: 'https', protocol: 'tcp', severity: 'low' },
    { port: 22, service: 'ssh', protocol: 'tcp', severity: 'high' },
    { port: 3306, service: 'mysql', protocol: 'tcp', severity: 'high' },
    { port: 8080, service: 'http-proxy', protocol: 'tcp', severity: 'medium' }
  ];
  
  for (const mockPort of mockPorts) {
    const vulnerability = await Vulnerability.create({
      scanId,
      title: `Open ${mockPort.service} service on port ${mockPort.port}`,
      description: `Service ${mockPort.service} is running on port ${mockPort.port}/${mockPort.protocol}. This port should be properly secured and only accessible to authorized users.`,
      severity: mockPort.severity,
      port: mockPort.port,
      service: mockPort.service,
      protocol: mockPort.protocol,
      evidence: `Service detected: ${mockPort.service} on port ${mockPort.port}`,
      solution: `Review and secure the ${mockPort.service} service configuration. Ensure proper authentication and access controls are in place.`,
      status: 'open'
    });
    
    vulnerabilities.push(vulnerability);
  }
  
  // Add some mock vulnerabilities
  const mockVulns = [
    {
      title: 'Weak SSL/TLS Configuration',
      description: 'The target uses outdated SSL/TLS protocols that may be vulnerable to attacks.',
      severity: 'high',
      solution: 'Upgrade to TLS 1.2 or higher and disable weak cipher suites.'
    },
    {
      title: 'Missing Security Headers',
      description: 'The web server is missing important security headers like X-Frame-Options and Content-Security-Policy.',
      severity: 'medium',
      solution: 'Configure the web server to include security headers.'
    }
  ];
  
  for (const mockVuln of mockVulns) {
    const vulnerability = await Vulnerability.create({
      scanId,
      title: mockVuln.title,
      description: mockVuln.description,
      severity: mockVuln.severity,
      solution: mockVuln.solution,
      status: 'open'
    });
    
    vulnerabilities.push(vulnerability);
  }
  
  return vulnerabilities;
};

module.exports = {
  runNmapScan,
  parseNmapOutput
};
