const fs = require('fs');
const path = require('path');
const { Scan, Vulnerability, User } = require('../models');

// Generate HTML report (PDF-like) for download
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
  
  // Generate HTML report
  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Security Report - ${scan.name}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: Arial, sans-serif; padding: 40px; color: #333; }
    .header { text-align: center; margin-bottom: 30px; border-bottom: 2px solid #2563eb; padding-bottom: 20px; }
    .header h1 { color: #1e40af; margin-bottom: 10px; }
    .header p { color: #666; }
    .summary { display: flex; gap: 20px; margin-bottom: 30px; }
    .summary-box { flex: 1; padding: 20px; border-radius: 8px; text-align: center; }
    .summary-box.critical { background: #fef2f2; border: 1px solid #fecaca; }
    .summary-box.high { background: #fff7ed; border: 1px solid #fed7aa; }
    .summary-box.medium { background: #fefce8; border: 1px solid #fef08a; }
    .summary-box.low { background: #f0fdf4; border: 1px solid #bbf7d0; }
    .summary-box.total { background: #f8fafc; border: 1px solid #e2e8f0; }
    .summary-box h2 { font-size: 32px; margin-bottom: 5px; }
    .summary-box.critical h2 { color: #dc2626; }
    .summary-box.high h2 { color: #ea580c; }
    .summary-box.medium h2 { color: #ca8a04; }
    .summary-box.low h2 { color: #16a34a; }
    .vulnerability { margin-bottom: 30px; border: 1px solid #e5e7eb; border-radius: 8px; overflow: hidden; }
    .vuln-header { padding: 15px; display: flex; align-items: center; gap: 15px; }
    .vuln-header.critical { background: #fef2f2; }
    .vuln-header.high { background: #fff7ed; }
    .vuln-header.medium { background: #fefce8; }
    .vuln-header.low { background: #f0fdf4; }
    .severity-badge { padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; }
    .severity-badge.critical { background: #dc2626; color: white; }
    .severity-badge.high { background: #ea580c; color: white; }
    .severity-badge.medium { background: #ca8a04; color: white; }
    .severity-badge.low { background: #16a34a; color: white; }
    .vuln-body { padding: 20px; }
    .vuln-body h4 { color: #374151; margin-bottom: 8px; }
    .vuln-body p { color: #6b7280; margin-bottom: 15px; }
    .code-block { background: #1f2937; color: #f3f4f6; padding: 15px; border-radius: 6px; font-family: monospace; font-size: 13px; overflow-x: auto; white-space: pre-wrap; margin-top: 10px; }
    .info-row { display: flex; gap: 20px; margin-bottom: 10px; }
    .info-row span { color: #6b7280; font-size: 14px; }
    .info-row strong { color: #374151; }
    .footer { margin-top: 40px; text-align: center; color: #9ca3af; font-size: 12px; border-top: 1px solid #e5e7eb; padding-top: 20px; }
  </style>
</head>
<body>
  <div class="header">
    <h1>Security Assessment Report</h1>
    <p><strong>Target:</strong> ${scan.target}</p>
    <p><strong>Generated:</strong> ${new Date().toLocaleString()}</p>
    <p><strong>Scanner:</strong> vulNSecure v1.0</p>
  </div>

  <h2 style="margin-bottom: 20px;">Executive Summary</h2>
  <p style="margin-bottom: 20px; color: #4b5563;">
    This report presents the findings of a security assessment performed on <strong>${scan.target}</strong>. 
    A total of <strong>${summary.total}</strong> vulnerabilities were identified, including 
    <strong>${summary.critical}</strong> critical and <strong>${summary.high}</strong> high severity issues 
    that require immediate attention.
  </p>

  <div class="summary">
    <div class="summary-box total">
      <h2>${summary.total}</h2>
      <p>Total Issues</p>
    </div>
    <div class="summary-box critical">
      <h2>${summary.critical}</h2>
      <p>Critical</p>
    </div>
    <div class="summary-box high">
      <h2>${summary.high}</h2>
      <p>High</p>
    </div>
    <div class="summary-box medium">
      <h2>${summary.medium}</h2>
      <p>Medium</p>
    </div>
    <div class="summary-box low">
      <h2>${summary.low}</h2>
      <p>Low</p>
    </div>
  </div>

  <h2 style="margin-bottom: 20px; margin-top: 40px;">Detailed Findings</h2>
  
  ${vulns.map((vuln, i) => `
  <div class="vulnerability">
    <div class="vuln-header ${vuln.severity}">
      <span class="severity-badge ${vuln.severity}">${vuln.severity.toUpperCase()}</span>
      <h3>${i + 1}. ${vuln.title}</h3>
    </div>
    <div class="vuln-body">
      <div class="info-row">
        <span><strong>URL:</strong> ${vuln.url || 'N/A'}</span>
      </div>
      <div class="info-row">
        <span><strong>CVSS Score:</strong> ${vuln.cvssScore || 'N/A'}</span>
        <span><strong>CWE:</strong> ${vuln.cveId || 'N/A'}</span>
        <span><strong>Category:</strong> ${vuln.category || 'N/A'}</span>
      </div>
      
      <h4>Description</h4>
      <p>${vuln.description}</p>
      
      <h4>Evidence</h4>
      <p>${vuln.evidence}</p>
      
      <h4>Remediation</h4>
      <p>${vuln.solution}</p>
      
      ${vuln.poc ? `
      <h4>Proof of Concept</h4>
      <div class="code-block">${vuln.poc}</div>
      ` : ''}
    </div>
  </div>
  `).join('')}

  <div class="footer">
    <p>Generated by vulNSecure - Vulnerability Scanning Platform</p>
    <p>This report is confidential and intended for authorized personnel only.</p>
  </div>
</body>
</html>
  `;
  
  // Save HTML file
  const reportsDir = path.join(__dirname, '../../reports');
  if (!fs.existsSync(reportsDir)) {
    fs.mkdirSync(reportsDir, { recursive: true });
  }
  
  const fileName = `report-${scanId}-${Date.now()}.html`;
  const filePath = path.join(reportsDir, fileName);
  fs.writeFileSync(filePath, html);
  
  return {
    filePath,
    fileName,
    fileSize: fs.statSync(filePath).size,
    summary
  };
};

module.exports = { generatePDFReport };
