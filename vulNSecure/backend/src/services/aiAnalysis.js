const { logger } = require('../utils/logger');

// AI-powered vulnerability analysis
const analyzeVulnerability = async (vulnerability) => {
  const category = vulnerability.category || '';
  const severity = vulnerability.severity || '';
  const title = vulnerability.title || '';
  
  const analysis = {
    riskAssessment: '',
    exploitability: '',
    businessImpact: '',
    realWorldExamples: [],
    remediationSteps: [],
    cvssBreakdown: '',
    owaspMapping: '',
    complianceImpact: []
  };
  
  // Risk Assessment
  analysis.riskAssessment = getRiskAssessment(severity, category);
  
  // Exploitability Analysis
  analysis.exploitability = getExploitability(category);
  
  // Business Impact
  analysis.businessImpact = getBusinessImpact(category);
  
  // Real-world examples
  analysis.realWorldExamples = getRealWorldExamples(category);
  
  // Remediation steps
  analysis.remediationSteps = getRemediationSteps(category);
  
  // CVSS breakdown
  analysis.cvssBreakdown = getCVSSBreakdown(category);
  
  // OWASP mapping
  analysis.owaspMapping = getOWASPMapping(category);
  
  // Compliance impact
  analysis.complianceImpact = getComplianceImpact(category);
  
  return analysis;
};

const getRiskAssessment = (severity, category) => {
  const risks = {
    'critical': 'CRITICAL RISK: This vulnerability poses immediate and severe threat to your application. Attackers can exploit this with minimal effort to gain full system access, steal sensitive data, or disrupt services. Immediate remediation required.',
    'high': 'HIGH RISK: This vulnerability can be exploited to cause significant damage. While it may require some user interaction or specific conditions, exploitation can lead to data breaches, account takeover, or system compromise. Address within 24-48 hours.',
    'medium': 'MEDIUM RISK: This vulnerability could be exploited as part of a chain attack or under specific conditions. While not immediately critical, it weakens overall security posture. Address within 1-2 weeks.',
    'low': 'LOW RISK: This vulnerability has limited direct impact but should be addressed as part of good security hygiene. May help attackers gather information for more sophisticated attacks.'
  };
  
  return risks[severity] || 'Risk assessment requires further analysis.';
};

const getExploitability = (category) => {
  const exploitability = {
    'sql-injection': {
      level: 'VERY HIGH',
      description: 'SQL Injection can be exploited using automated tools like SQLMap. Requires minimal skill level. Publicly available exploits and techniques are well-documented.',
      tools: ['SQLMap', 'Havij', 'jSQL', 'Burp Suite'],
      skill: 'Beginner',
      time: 'Minutes to hours'
    },
    'xss': {
      level: 'HIGH',
      description: 'Cross-Site Scripting can be exploited via social engineering or direct injection. Victim interaction required for reflected XSS.',
      tools: ['BeEF', 'XSS Hunter', 'Burp Suite'],
      skill: 'Beginner',
      time: 'Minutes to hours'
    },
    'ssrf': {
      level: 'HIGH',
      description: 'Server-Side Request Forgery allows access to internal services. Can lead to cloud credential theft on AWS/Azure/GCP.',
      tools: ['Burp Suite', 'SSRFMap', 'Gopherus'],
      skill: 'Intermediate',
      time: 'Hours'
    },
    'command-injection': {
      level: 'VERY HIGH',
      description: 'OS Command Injection provides direct command execution. Complete system compromise is possible.',
      tools: ['Manual testing', 'Commix', 'Burp Suite'],
      skill: 'Beginner',
      time: 'Minutes'
    },
    'idor': {
      level: 'HIGH',
      description: 'Insecure Direct Object Reference allows unauthorized access to other users data. No special tools needed.',
      tools: ['Browser', 'Burp Suite'],
      skill: 'Beginner',
      time: 'Minutes'
    },
    'cors': {
      level: 'MEDIUM',
      description: 'CORS misconfiguration requires victim to visit attacker website. Can be exploited via CSRF.',
      tools: ['Browser', 'Custom HTML page'],
      skill: 'Intermediate',
      time: 'Hours'
    }
  };
  
  return exploitability[category] || { level: 'MEDIUM', description: 'Exploitability depends on specific implementation.' };
};

const getBusinessImpact = (category) => {
  const impacts = {
    'sql-injection': [
      'Complete database compromise',
      'Customer data theft (PII, financial)',
      'Authentication bypass',
      'Regulatory fines (GDPR: up to 4% revenue, PCI-DSS: $5k-$100k/month)',
      'Reputational damage',
      'Legal liability for data breach'
    ],
    'xss': [
      'User account takeover',
      'Session hijacking',
      'Credential theft via phishing',
      'Website defacement',
      'Malware distribution',
      'Compliance violations'
    ],
    'ssrf': [
      'Internal network access',
      'AWS/Azure/GCP credential theft',
      'Cloud infrastructure compromise',
      'Database access',
      'Microservices exploitation',
      'Data exfiltration'
    ],
    'command-injection': [
      'Complete server compromise',
      'Data theft',
      'Ransomware deployment',
      'Lateral movement to other systems',
      'Crypto mining',
      'Botnet recruitment'
    ]
  };
  
  return impacts[category] || ['Potential security breach', 'Data exposure risk'];
};

const getRealWorldExamples = (category) => {
  const examples = {
    'sql-injection': [
      { company: 'Equifax', year: 2017, impact: '147 million records exposed, $1.4 billion in damages' },
      { company: 'British Airways', year: 2018, impact: '380,000 payment cards stolen, £20 million fine' },
      { company: 'MOVEit', year: 2023, impact: 'SQL injection in file transfer affected thousands of organizations' },
      { company: 'Heartland Payment', year: 2009, impact: '130 million credit cards stolen' }
    ],
    'xss': [
      { company: 'British Airways', year: 2018, impact: 'Magecart XSS attack stole payment data' },
      { company: 'Magecart', year: 2019, impact: 'Thousands of e-commerce sites compromised via XSS' },
      { company: 'Samy (MySpace)', year: 2005, impact: 'XSS worm spread to 1 million users in 20 hours' }
    ],
    'ssrf': [
      { company: 'Capital One', year: 2019, impact: 'SSRF on AWS exposed 100 million customer records' },
      { company: 'Shopify', year: 2020, impact: 'SSRF exposed internal infrastructure' },
      { company: 'GitLab', year: 2021, impact: 'SSRF allowed access to internal services' }
    ],
    'command-injection': [
      { company: 'Shellshock', year: 2014, impact: 'Bash vulnerability affected millions of servers' },
      { company: 'Juniper VPN', year: 2015, impact: 'Command injection in VPN appliance' },
      { company: 'Cisco ASA', year: 2016, impact: 'Remote code execution via command injection' }
    ]
  };
  
  return examples[category] || [{ company: 'Multiple organizations', year: 2023, impact: 'Various security breaches reported' }];
};

const getRemediationSteps = (category) => {
  const steps = {
    'sql-injection': [
      '1. IMMEDIATE: Implement parameterized queries for all database operations',
      '2. HIGH: Use an ORM framework (Sequelize, SQLAlchemy, Hibernate)',
      '3. MEDIUM: Add input validation for all user inputs',
      '4. MEDIUM: Implement WAF rules to block SQL injection patterns',
      '5. LOW: Review and audit all database queries',
      '6. LOW: Apply principle of least privilege to database accounts'
    ],
    'xss': [
      '1. IMMEDIATE: Implement output encoding for all user-generated content',
      '2. HIGH: Add Content-Security-Policy headers',
      '3. HIGH: Set HttpOnly and Secure flags on cookies',
      '4. MEDIUM: Use modern frameworks with auto-escaping',
      '5. MEDIUM: Implement input validation',
      '6. LOW: Add X-XSS-Protection header'
    ],
    'ssrf': [
      '1. IMMEDIATE: Validate and whitelist allowed URLs',
      '2. HIGH: Block access to internal IPs and cloud metadata',
      '3. HIGH: Disable unnecessary URL schemes (file://, gopher://)',
      '4. MEDIUM: Use network-level controls',
      '5. MEDIUM: Implement proper error handling',
      '6. LOW: Monitor outbound requests'
    ],
    'command-injection': [
      '1. IMMEDIATE: Never pass user input to shell commands',
      '2. HIGH: Use safe APIs instead of shell execution',
      '3. HIGH: Implement strict input validation',
      '4. MEDIUM: Use allowlists for command arguments',
      '5. MEDIUM: Run with minimal privileges',
      '6. LOW: Monitor and log command execution'
    ]
  };
  
  return steps[category] || ['Review and fix the identified vulnerability', 'Follow OWASP guidelines', 'Implement defense in depth'];
};

const getCVSSBreakdown = (category) => {
  return {
    'sql-injection': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 Critical)',
    'xss': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N (6.1 Medium)',
    'ssrf': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N (9.1 Critical)',
    'command-injection': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 Critical)',
    'idor': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.5 Medium)'
  }[category] || 'CVSS score varies based on specific implementation';
};

const getOWASPMapping = (category) => {
  const mapping = {
    'sql-injection': 'A03:2021 - Injection',
    'xss': 'A03:2021 - Injection',
    'ssrf': 'A10:2021 - Server-Side Request Forgery',
    'command-injection': 'A03:2021 - Injection',
    'idor': 'A01:2021 - Broken Access Control',
    'cors': 'A05:2021 - Security Misconfiguration',
    'headers': 'A05:2021 - Security Misconfiguration',
    'exposure': 'A02:2021 - Cryptographic Failures',
    'open-redirect': 'A01:2021 - Broken Access Control'
  };
  
  return mapping[category] || 'A05:2021 - Security Misconfiguration';
};

const getComplianceImpact = (category) => {
  const compliance = {
    'sql-injection': ['PCI-DSS 6.5.1', 'OWASP Top 10 A03', 'HIPAA Technical Safeguards'],
    'xss': ['PCI-DSS 6.5.7', 'OWASP Top 10 A03', 'HIPAA Technical Safeguards'],
    'ssrf': ['OWASP Top 10 A10', 'SOC 2 CC6.1'],
    'command-injection': ['PCI-DSS 6.5.1', 'OWASP Top 10 A03', 'NIST 800-53 SI-10'],
    'exposure': ['PCI-DSS 3.4', 'GDPR Article 32', 'HIPAA Encryption']
  };
  
  return compliance[category] || ['OWASP Top 10', 'Security Best Practices'];
};

module.exports = { analyzeVulnerability };
