const nodemailer = require('nodemailer');
const { logger } = require('../utils/logger');

class EmailService {
  constructor() {
    // Create transporter (configure with your SMTP settings)
    this.transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST || 'smtp.gmail.com',
      port: process.env.SMTP_PORT || 587,
      secure: false,
      auth: {
        user: process.env.SMTP_USER || 'your-email@gmail.com',
        pass: process.env.SMTP_PASS || 'your-app-password'
      }
    });
    
    this.fromEmail = process.env.FROM_EMAIL || 'noreply@vulnsecure.com';
  }

  // Send scan completion notification
  async sendScanCompleteNotification(user, scan, vulnerabilities) {
    const vulnCount = vulnerabilities.length;
    const criticalCount = vulnerabilities.filter(v => v.severity === 'critical').length;
    
    const subject = `Scan Completed: ${scan.name} - ${vulnCount} vulnerabilities found`;
    const html = `
      <h2>Scan Completed Successfully</h2>
      <p>Hello ${user.firstName},</p>
      <p>Your security scan has been completed.</p>
      
      <h3>Scan Details:</h3>
      <ul>
        <li><strong>Scan Name:</strong> ${scan.name}</li>
        <li><strong>Target:</strong> ${scan.target}</li>
        <li><strong>Type:</strong> ${scan.type}</li>
        <li><strong>Status:</strong> ${scan.status}</li>
      </ul>
      
      <h3>Vulnerability Summary:</h3>
      <ul>
        <li style="color: red;">Critical: ${criticalCount}</li>
        <li style="color: orange;">High: ${vulnerabilities.filter(v => v.severity === 'high').length}</li>
        <li style="color: gold;">Medium: ${vulnerabilities.filter(v => v.severity === 'medium').length}</li>
        <li style="color: green;">Low: ${vulnerabilities.filter(v => v.severity === 'low').length}</li>
      </ul>
      
      <p>Please log in to view the detailed results.</p>
      <p><a href="${process.env.FRONTEND_URL || 'http://localhost:3000'}/scans/${scan.id}">View Scan Results</a></p>
      
      <hr>
      <p style="color: #666; font-size: 12px;">vulNSecure Platform</p>
    `;

    return this.sendEmail(user.email, subject, html);
  }

  // Send vulnerability alert
  async sendVulnerabilityAlert(user, vulnerability, scan) {
    const severityColors = {
      critical: 'red',
      high: 'orange',
      medium: 'gold',
      low: 'green'
    };
    
    const subject = `🚨 ALERT: ${vulnerability.severity.toUpperCase()} Vulnerability Detected`;
    const html = `
      <h2 style="color: ${severityColors[vulnerability.severity]}">Security Vulnerability Alert</h2>
      <p>Hello ${user.firstName},</p>
      <p>A new vulnerability has been detected that requires your attention.</p>
      
      <h3>Vulnerability Details:</h3>
      <ul>
        <li><strong>Title:</strong> ${vulnerability.title}</li>
        <li><strong>Severity:</strong> <span style="color: ${severityColors[vulnerability.severity]}; font-weight: bold;">${vulnerability.severity.toUpperCase()}</span></li>
        <li><strong>Description:</strong> ${vulnerability.description}</li>
        <li><strong>Target:</strong> ${scan?.target || 'N/A'}</li>
      </ul>
      
      <p>Please take immediate action to address this vulnerability.</p>
      <p><a href="${process.env.FRONTEND_URL || 'http://localhost:3000'}/vulnerabilities/${vulnerability.id}">View Details</a></p>
      
      <hr>
      <p style="color: #666; font-size: 12px;">vulNSecure Platform - Security Alert</p>
    `;

    return this.sendEmail(user.email, subject, html);
  }

  // Send data leak alert
  async sendLeakAlert(user, leak) {
    const subject = `⚠️ ALERT: Data Leak Detected - ${leak.title}`;
    const html = `
      <h2 style="color: red">Data Leak Alert</h2>
      <p>Hello ${user.firstName},</p>
      <p>Potential data leak has been detected.</p>
      
      <h3>Details:</h3>
      <ul>
        <li><strong>Title:</strong> ${leak.title}</li>
        <li><strong>Severity:</strongstrong> ${leak.severity}</li>
        <li><strong>Domain:</strong> ${leak.domain}</li>
        <li><strong>Source:</strong> ${leak.source}</li>
      </ul>
      
      <p><a href="${process.env.FRONTEND_URL || 'http://localhost:3000'}/leaks/${leak.id}">View Details</a></p>
    `;

    return this.sendEmail(user.email, subject, html);
  }

  // Send weekly summary
  async sendWeeklySummary(user, stats) {
    const subject = `📊 Weekly Security Report - ${stats.scansCompleted} scans completed`;
    const html = `
      <h2>Weekly Security Summary</h2>
      <p>Hello ${user.firstName},</p>
      <p>Here's your weekly security overview:</p>
      
      <h3>Activity:</h3>
      <ul>
        <li>Scans Completed: ${stats.scansCompleted}</li>
        <li>Vulnerabilities Found: ${stats.vulnerabilitiesFound}</li>
        <li>Critical: ${stats.critical}</li>
        <li>High: ${stats.high}</li>
      </ul>
      
      <p><a href="${process.env.FRONTEND_URL || 'http://localhost:3000'}/dashboard">View Dashboard</a></p>
    `;

    return this.sendEmail(user.email, subject, html);
  }

  // Generic send email method
  async sendEmail(to, subject, html) {
    try {
      const info = await this.transporter.sendMail({
        from: this.fromEmail,
        to,
        subject,
        html
      });
      
      logger.info('Email sent successfully', { to, subject, messageId: info.messageId });
      return { success: true, messageId: info.messageId };
    } catch (error) {
      logger.error('Email send failed', { to, subject, error: error.message });
      return { success: false, error: error.message };
    }
  }
}

module.exports = new EmailService();
