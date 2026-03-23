const axios = require('axios');
const { logger } = require('../utils/logger');

class SlackNotifier {
  constructor(webhookUrl) {
    this.webhookUrl = webhookUrl;
  }

  async sendScanComplete(scan) {
    if (!this.webhookUrl) return;

    const message = {
      blocks: [
        {
          type: 'header',
          text: {
            type: 'plain_text',
            text: '🔍 Scan Completed',
            emoji: true
          }
        },
        {
          type: 'section',
          fields: [
            { type: 'mrkdwn', text: `*Scan Name:*\n${scan.name}` },
            { type: 'mrkdwn', text: `*Target:*\n${scan.target}` },
            { type: 'mrkdwn', text: `*Status:*\n${scan.status}` },
            { type: 'mrkdwn', text: `*Vulnerabilities:*\n${scan.summary?.vulnerabilities || 0}` }
          ]
        },
        {
          type: 'section',
          fields: [
            { type: 'mrkdwn', text: `*Critical:*\n${scan.summary?.severityBreakdown?.critical || 0}` },
            { type: 'mrkdwn', text: `*High:*\n${scan.summary?.severityBreakdown?.high || 0}` },
            { type: 'mrkdwn', text: `*Medium:*\n${scan.summary?.severityBreakdown?.medium || 0}` },
            { type: 'mrkdwn', text: `*Low:*\n${scan.summary?.severityBreakdown?.low || 0}` }
          ]
        },
        {
          type: 'actions',
          elements: [
            {
              type: 'button',
              text: { type: 'plain_text', text: 'View Scan Results' },
              url: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/scans/${scan.id}`
            }
          ]
        }
      ]
    };

    try {
      await axios.post(this.webhookUrl, message);
      logger.info('Slack notification sent', { scanId: scan.id });
    } catch (error) {
      logger.error('Failed to send Slack notification', { error: error.message });
    }
  }

  async sendVulnerabilityAlert(vulnerability) {
    if (!this.webhookUrl) return;

    const severityEmoji = {
      critical: '🔴',
      high: '🟠',
      medium: '🟡',
      low: '🟢'
    };

    const message = {
      blocks: [
        {
          type: 'header',
          text: {
            type: 'plain_text',
            text: `${severityEmoji[vulnerability.severity] || '⚠️'} New Vulnerability Found`,
            emoji: true
          }
        },
        {
          type: 'section',
          fields: [
            { type: 'mrkdwn', text: `*Title:*\n${vulnerability.title}` },
            { type: 'mrkdwn', text: `*Severity:*\n${vulnerability.severity?.toUpperCase()}` },
            { type: 'mrkdwn', text: `*URL:*\n${vulnerability.url}` },
            { type: 'mrkdwn', text: `*Category:*\n${vulnerability.category || 'N/A'}` }
          ]
        },
        {
          type: 'context',
          elements: [
            { type: 'mrkdwn', text: `Description: ${vulnerability.description?.substring(0, 100)}...` }
          ]
        }
      ]
    };

    try {
      await axios.post(this.webhookUrl, message);
    } catch (error) {
      logger.error('Failed to send Slack vulnerability alert', { error: error.message });
    }
  }
}

class TeamsNotifier {
  constructor(webhookUrl) {
    this.webhookUrl = webhookUrl;
  }

  async sendScanComplete(scan) {
    if (!this.webhookUrl) return;

    const message = {
      '@type': 'MessageCard',
      '@context': 'http://schema.org/extensions',
      themeColor: '0076D7',
      summary: `Scan Completed: ${scan.name}`,
      sections: [
        {
          activityTitle: '🔍 Scan Completed',
          facts: [
            { name: 'Scan Name', value: scan.name },
            { name: 'Target', value: scan.target },
            { name: 'Status', value: scan.status },
            { name: 'Vulnerabilities', value: scan.summary?.vulnerabilities || 0 }
          ]
        }
      ],
      potentialAction: [
        {
          '@type': 'OpenUri',
          name: 'View Results',
          targets: [
            { os: 'default', uri: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/scans/${scan.id}` }
          ]
        }
      ]
    };

    try {
      await axios.post(this.webhookUrl, message);
      logger.info('Teams notification sent', { scanId: scan.id });
    } catch (error) {
      logger.error('Failed to send Teams notification', { error: error.message });
    }
  }

  async sendVulnerabilityAlert(vulnerability) {
    if (!this.webhookUrl) return;

    const severityColors = { critical: 'FF0000', high: 'FFA500', medium: 'FFFF00', low: '00FF00' };

    const message = {
      '@type': 'MessageCard',
      '@context': 'http://schema.org/extensions',
      themeColor: severityColors[vulnerability.severity] || '0076D7',
      summary: `Vulnerability: ${vulnerability.title}`,
      sections: [
        {
          activityTitle: `⚠️ New ${vulnerability.severity?.toUpperCase()} Vulnerability`,
          facts: [
            { name: 'Title', value: vulnerability.title },
            { name: 'Severity', value: vulnerability.severity },
            { name: 'URL', value: vulnerability.url },
            { name: 'Category', value: vulnerability.category || 'N/A' }
          ]
        }
      ]
    };

    try {
      await axios.post(this.webhookUrl, message);
    } catch (error) {
      logger.error('Failed to send Teams vulnerability alert', { error: error.message });
    }
  }
}

class JiraIntegration {
  constructor(config) {
    this.config = config;
    this.baseUrl = config.baseUrl;
    this.email = config.email;
    this.apiToken = config.apiToken;
    this.projectKey = config.projectKey;
  }

  async createTicket(vulnerability) {
    if (!this.baseUrl || !this.apiToken) return null;

    const issueData = {
      fields: {
        project: { key: this.projectKey },
        summary: `[${vulnerability.severity?.toUpperCase()}] ${vulnerability.title}`,
        description: `
h3. Vulnerability Details
*Severity:* ${vulnerability.severity}
*Category:* ${vulnerability.category || 'N/A'}
*URL:* ${vulnerability.url}

h3. Description
${vulnerability.description}

h3. Evidence
${vulnerability.evidence || 'N/A'}

h3. Solution
${vulnerability.solution || 'N/A'}
        `.trim(),
        issuetype: { name: 'Bug' },
        priority: this.getPriority(vulnerability.severity)
      }
    };

    try {
      const response = await axios.post(
        `${this.baseUrl}/rest/api/3/issue`,
        issueData,
        {
          headers: {
            'Authorization': `Basic ${Buffer.from(`${this.email}:${this.apiToken}`).toString('base64')}`,
            'Content-Type': 'application/json'
          }
        }
      );

      logger.info('Jira ticket created', { ticketKey: response.data.key, vulnerabilityId: vulnerability.id });
      return { key: response.data.key, url: `${this.baseUrl}/browse/${response.data.key}` };
    } catch (error) {
      logger.error('Failed to create Jira ticket', { error: error.message });
      return null;
    }
  }

  getPriority(severity) {
    const priorities = {
      critical: 'Highest',
      high: 'High',
      medium: 'Medium',
      low: 'Low'
    };
    return priorities[severity] || 'Medium';
  }
}

module.exports = {
  SlackNotifier,
  TeamsNotifier,
  JiraIntegration
};
