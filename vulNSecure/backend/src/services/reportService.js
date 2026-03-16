const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');
const { Report, Scan, Vulnerability, Leak, User } = require('../models');
const { logger } = require('../utils/logger');

const generatePDFReport = async (reportId, type, scanId, configuration = {}) => {
  try {
    const report = await Report.findByPk(reportId);
    if (!report) {
      throw new Error('Report not found');
    }

    // Create reports directory if it doesn't exist
    const reportsDir = path.join(process.cwd(), 'reports');
    if (!fs.existsSync(reportsDir)) {
      fs.mkdirSync(reportsDir, { recursive: true });
    }

    const fileName = `report_${reportId}_${Date.now()}.pdf`;
    const filePath = path.join(reportsDir, fileName);

    // Create PDF document
    const doc = new PDFDocument({ margin: 50 });
    const stream = fs.createWriteStream(filePath);
    doc.pipe(stream);

    // Add header
    doc.fontSize(20).text('vulNSecure Security Report', { align: 'center' });
    doc.fontSize(12).text(`Generated: ${new Date().toLocaleString()}`, { align: 'center' });
    doc.moveDown(2);

    // Add report details
    doc.fontSize(16).text('Report Details', { underline: true });
    doc.fontSize(12);
    doc.text(`Title: ${report.title}`);
    doc.text(`Type: ${report.type}`);
    doc.text(`Format: ${report.format}`);
    doc.moveDown();

    if (scanId) {
      const scan = await Scan.findByPk(scanId, {
        include: [
          {
            model: User,
            as: 'user',
            attributes: ['username', 'firstName', 'lastName']
          }
        ]
      });

      if (scan) {
        doc.fontSize(16).text('Scan Information', { underline: true });
        doc.fontSize(12);
        doc.text(`Scan Name: ${scan.name}`);
        doc.text(`Target: ${scan.target}`);
        doc.text(`Type: ${scan.type}`);
        doc.text(`Status: ${scan.status}`);
        doc.text(`Started: ${scan.startTime ? scan.startTime.toLocaleString() : 'N/A'}`);
        doc.text(`Completed: ${scan.endTime ? scan.endTime.toLocaleString() : 'N/A'}`);
        doc.text(`Scan By: ${scan.user.firstName} ${scan.user.lastName} (${scan.user.username})`);
        doc.moveDown();
      }
    }

    // Add vulnerabilities section
    if (type === 'scan' || type === 'combined') {
      const vulnerabilities = await Vulnerability.findAll({
        where: scanId ? { scanId } : {},
        include: [{
          model: Scan,
          as: 'scan',
          attributes: ['name', 'target']
        }],
        order: [['severity', 'DESC'], ['createdAt', 'DESC']]
      });

      if (vulnerabilities.length > 0) {
        doc.fontSize(16).text('Vulnerabilities Found', { underline: true });
        doc.moveDown();

        // Summary
        const severityCounts = {
          critical: vulnerabilities.filter(v => v.severity === 'critical').length,
          high: vulnerabilities.filter(v => v.severity === 'high').length,
          medium: vulnerabilities.filter(v => v.severity === 'medium').length,
          low: vulnerabilities.filter(v => v.severity === 'low').length,
          info: vulnerabilities.filter(v => v.severity === 'info').length
        };

        doc.fontSize(14).text('Summary', { underline: true });
        doc.fontSize(12);
        doc.text(`Total Vulnerabilities: ${vulnerabilities.length}`);
        doc.text(`Critical: ${severityCounts.critical}`);
        doc.text(`High: ${severityCounts.high}`);
        doc.text(`Medium: ${severityCounts.medium}`);
        doc.text(`Low: ${severityCounts.low}`);
        doc.text(`Info: ${severityCounts.info}`);
        doc.moveDown();

        // Detailed vulnerabilities
        doc.fontSize(14).text('Detailed Findings', { underline: true });
        doc.moveDown();

        vulnerabilities.forEach((vuln, index) => {
          doc.fontSize(12);
          doc.text(`${index + 1}. ${vuln.title}`, { underline: true });
          doc.text(`Severity: ${vuln.severity.toUpperCase()}`);
          if (vuln.cvssScore) {
            doc.text(`CVSS Score: ${vuln.cvssScore}`);
          }
          if (vuln.port) {
            doc.text(`Port: ${vuln.port}/${vuln.protocol || 'tcp'}`);
          }
          if (vuln.service) {
            doc.text(`Service: ${vuln.service}`);
          }
          doc.text(`Description: ${vuln.description}`);
          if (vuln.evidence) {
            doc.text(`Evidence: ${vuln.evidence}`);
          }
          if (vuln.solution) {
            doc.text(`Solution: ${vuln.solution}`);
          }
          doc.moveDown();
        });
      }
    }

    // Add leaks section
    if (type === 'leak' || type === 'combined') {
      const leaks = await Leak.findAll({
        where: scanId ? { scanId } : {},
        include: [{
          model: Scan,
          as: 'scan',
          attributes: ['name', 'target']
        }],
        order: [['severity', 'DESC'], ['createdAt', 'DESC']]
      });

      if (leaks.length > 0) {
        doc.addPage();
        doc.fontSize(16).text('Data Leaks Found', { underline: true });
        doc.moveDown();

        // Summary
        const leakSeverityCounts = {
          critical: leaks.filter(l => l.severity === 'critical').length,
          high: leaks.filter(l => l.severity === 'high').length,
          medium: leaks.filter(l => l.severity === 'medium').length,
          low: leaks.filter(l => l.severity === 'low').length
        };

        doc.fontSize(14).text('Summary', { underline: true });
        doc.fontSize(12);
        doc.text(`Total Leaks: ${leaks.length}`);
        doc.text(`Critical: ${leakSeverityCounts.critical}`);
        doc.text(`High: ${leakSeverityCounts.high}`);
        doc.text(`Medium: ${leakSeverityCounts.medium}`);
        doc.text(`Low: ${leakSeverityCounts.low}`);
        doc.moveDown();

        // Detailed leaks
        doc.fontSize(14).text('Detailed Findings', { underline: true });
        doc.moveDown();

        leaks.forEach((leak, index) => {
          doc.fontSize(12);
          doc.text(`${index + 1}. ${leak.title}`, { underline: true });
          doc.text(`Severity: ${leak.severity.toUpperCase()}`);
          doc.text(`Classification: ${leak.classification}`);
          doc.text(`Confidence: ${(leak.confidence * 100).toFixed(1)}%`);
          doc.text(`Source: ${leak.source}`);
          doc.text(`Description: ${leak.content.substring(0, 200)}${leak.content.length > 200 ? '...' : ''}`);
          if (leak.organization) {
            doc.text(`Organization: ${leak.organization}`);
          }
          doc.moveDown();
        });
      }
    }

    // Add recommendations
    doc.addPage();
    doc.fontSize(16).text('Recommendations', { underline: true });
    doc.moveDown();
    doc.fontSize(12);
    doc.text('1. Address critical and high severity vulnerabilities immediately');
    doc.text('2. Implement regular security scanning and monitoring');
    doc.text('3. Keep all systems and software updated');
    doc.text('4. Implement proper access controls and authentication');
    doc.text('5. Monitor for data leaks and unauthorized access');
    doc.text('6. Establish incident response procedures');
    doc.text('7. Conduct regular security awareness training');
    doc.moveDown();

    // Add footer
    doc.fontSize(10);
    doc.text('This report was generated by vulNSecure Platform', { align: 'center' });
    doc.text('For questions or support, contact your security team', { align: 'center' });

    // Finalize PDF
    doc.end();

    return new Promise((resolve, reject) => {
      stream.on('finish', async () => {
        try {
          const stats = fs.statSync(filePath);
          const fileSize = stats.size;

          resolve({
            filePath,
            fileName,
            fileSize,
            summary: {
              generatedAt: new Date(),
              reportType: type,
              scanId: scanId || null
            }
          });
        } catch (error) {
          reject(error);
        }
      });

      stream.on('error', reject);
    });

  } catch (error) {
    logger.error('PDF generation failed', { reportId, error: error.message });
    throw error;
  }
};

module.exports = {
  generatePDFReport
};
