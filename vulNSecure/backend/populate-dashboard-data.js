const { sequelize } = require('./src/config/database');
const { Scan, Vulnerability, Leak, User } = require('./src/models');

async function populateDashboardData() {
  try {
    console.log('🔄 Starting dashboard data population...');

    // First, get existing scans to associate vulnerabilities and leaks with
    const scans = await Scan.findAll({
      include: [{
        model: User,
        as: 'user',
        attributes: ['id', 'username']
      }]
    });

    if (scans.length === 0) {
      console.log('❌ No scans found. Creating sample scans first...');
      
      // Get the first user (admin)
      const user = await User.findOne({ where: { role: 'admin' } });
      if (!user) {
        console.log('❌ No admin user found. Please create a user first.');
        return;
      }

      // Create sample scans
      const sampleScans = await Scan.bulkCreate([
        {
          userId: user.id,
          name: 'Production Web Application Scan',
          type: 'web',
          target: 'https://example.com',
          status: 'completed',
          progress: 100,
          startTime: new Date(Date.now() - 24 * 60 * 60 * 1000), // 1 day ago
          endTime: new Date(Date.now() - 23 * 60 * 60 * 1000),
          results: { totalChecks: 150, vulnerabilitiesFound: 12 }
        },
        {
          userId: user.id,
          name: 'Network Infrastructure Scan',
          type: 'network',
          target: '192.168.1.0/24',
          status: 'completed',
          progress: 100,
          startTime: new Date(Date.now() - 48 * 60 * 60 * 1000), // 2 days ago
          endTime: new Date(Date.now() - 47 * 60 * 60 * 1000),
          results: { portsScanned: 65535, servicesFound: 25 }
        },
        {
          userId: user.id,
          name: 'Dark Web Monitoring',
          type: 'darkweb',
          target: 'company-domain.com',
          status: 'completed',
          progress: 100,
          startTime: new Date(Date.now() - 72 * 60 * 60 * 1000), // 3 days ago
          endTime: new Date(Date.now() - 71 * 60 * 60 * 1000),
          results: { sitesMonitored: 500, leaksFound: 8 }
        }
      ]);

      console.log(`✅ Created ${sampleScans.length} sample scans`);
      scans.push(...sampleScans);
    }

    console.log(`📊 Found ${scans.length} scans to populate with data`);

    // Sample vulnerabilities with different severity levels
    const vulnerabilityTemplates = [
      {
        title: 'SQL Injection in Login Form',
        description: 'The login form is vulnerable to SQL injection attacks, allowing attackers to bypass authentication.',
        severity: 'critical',
        cvssScore: 9.8,
        cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        url: '/login',
        method: 'POST',
        parameter: 'username',
        evidence: 'Payload: admin\' OR \'1\'=\'1\' -- resulted in successful login bypass',
        solution: 'Use parameterized queries and input validation to prevent SQL injection attacks.',
        references: ['https://owasp.org/www-community/attacks/SQL_Injection']
      },
      {
        title: 'Cross-Site Scripting (XSS) in Search Function',
        description: 'The search functionality reflects user input without proper sanitization, leading to stored XSS.',
        severity: 'high',
        cvssScore: 8.8,
        cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
        url: '/search',
        method: 'GET',
        parameter: 'q',
        evidence: 'Payload: <script>alert(\'XSS\')</script> executed successfully',
        solution: 'Implement proper input validation and output encoding to prevent XSS attacks.',
        references: ['https://owasp.org/www-community/attacks/xss/']
      },
      {
        title: 'Insecure Direct Object Reference',
        description: 'User profile endpoints allow access to other users\' data by manipulating the user ID parameter.',
        severity: 'high',
        cvssScore: 7.5,
        cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
        url: '/api/users/{id}',
        method: 'GET',
        parameter: 'id',
        evidence: 'Accessing /api/users/123 returns sensitive data for user 123 without authorization check',
        solution: 'Implement proper authorization checks to ensure users can only access their own data.',
        references: ['https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control']
      },
      {
        title: 'Weak Password Policy',
        description: 'The application allows weak passwords that can be easily brute-forced.',
        severity: 'medium',
        cvssScore: 6.5,
        cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
        evidence: 'Password "123456" was accepted during registration',
        solution: 'Implement strong password requirements including minimum length, complexity, and common password blacklists.',
        references: ['https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication']
      },
      {
        title: 'Missing Security Headers',
        description: 'The application is missing important security headers like X-Frame-Options and Content-Security-Policy.',
        severity: 'medium',
        cvssScore: 5.3,
        cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N',
        evidence: 'Response headers analysis shows missing X-Frame-Options, X-Content-Type-Options, and CSP headers',
        solution: 'Configure web server or application to include security headers to prevent various attacks.',
        references: ['https://owasp.org/www-project-secure-headers/']
      },
      {
        title: 'Information Disclosure in Error Messages',
        description: 'Detailed error messages reveal sensitive information about the application structure.',
        severity: 'low',
        cvssScore: 3.7,
        cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',
        evidence: 'Database error: "Table \'users\' doesn\'t exist in database \'production_db\'" exposed in 500 error',
        solution: 'Implement generic error messages for users and log detailed errors server-side only.',
        references: ['https://owasp.org/www-community/Improper_Error_Handling']
      },
      {
        title: 'Outdated Software Components',
        description: 'The application uses outdated versions of third-party libraries with known vulnerabilities.',
        severity: 'high',
        cvssScore: 8.1,
        cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
        evidence: 'jQuery version 1.8.3 detected, which has multiple known XSS vulnerabilities',
        solution: 'Update all third-party libraries to their latest secure versions and implement dependency scanning.',
        references: ['https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities']
      },
      {
        title: 'Unencrypted Data Transmission',
        description: 'Sensitive data is transmitted over unencrypted HTTP connections.',
        severity: 'critical',
        cvssScore: 9.1,
        cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
        evidence: 'Login credentials sent over HTTP without encryption on /api/auth/login',
        solution: 'Implement HTTPS for all communications and redirect HTTP traffic to HTTPS.',
        references: ['https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure']
      }
    ];

    // Sample data leaks with different severity levels
    const leakTemplates = [
      {
        source: 'Pastebin',
        url: 'https://pastebin.com/abc123',
        title: 'Database Credentials Exposed',
        content: 'Production database credentials found in public paste including username, password, and connection string.',
        classification: 'credentials',
        severity: 'critical',
        confidence: 0.95,
        entities: { emails: ['admin@company.com'], databases: ['prod_db'] },
        extractedData: { username: 'db_admin', host: 'prod-db.company.com' },
        keywords: ['password', 'database', 'production'],
        organization: 'Company Inc'
      },
      {
        source: 'GitHub',
        url: 'https://github.com/user/repo/commit/xyz789',
        title: 'API Keys in Source Code',
        content: 'AWS access keys and secret keys found in committed source code.',
        classification: 'credentials',
        severity: 'critical',
        confidence: 0.98,
        entities: { aws_keys: ['AKIA...'], services: ['AWS S3', 'AWS EC2'] },
        extractedData: { access_key: 'AKIA1234567890', region: 'us-east-1' },
        keywords: ['aws', 'access_key', 'secret_key'],
        organization: 'Company Inc'
      },
      {
        source: 'Dark Web Forum',
        url: 'http://darkforum.onion/thread/456',
        title: 'Employee Personal Information',
        content: 'Employee names, email addresses, and phone numbers being sold on dark web marketplace.',
        classification: 'pii',
        severity: 'high',
        confidence: 0.87,
        entities: { emails: ['john.doe@company.com', 'jane.smith@company.com'], phones: ['+1-555-0123'] },
        extractedData: { employee_count: 150, department: 'Engineering' },
        keywords: ['employee', 'personal', 'contact'],
        organization: 'Company Inc'
      },
      {
        source: 'Telegram Channel',
        url: 'https://t.me/leaks_channel/789',
        title: 'Customer Credit Card Data',
        content: 'Customer credit card numbers and CVV codes found in leaked database dump.',
        classification: 'financial',
        severity: 'critical',
        confidence: 0.92,
        entities: { card_numbers: ['4532-****-****-1234'], customers: 5000 },
        extractedData: { breach_date: '2024-01-15', affected_customers: 5000 },
        keywords: ['credit_card', 'cvv', 'customer_data'],
        organization: 'Company Inc'
      },
      {
        source: 'Discord Server',
        url: 'https://discord.gg/abc123',
        title: 'Internal Documents Shared',
        content: 'Confidential business documents and strategic plans shared in public Discord server.',
        classification: 'corporate',
        severity: 'high',
        confidence: 0.78,
        entities: { documents: ['Q4_Strategy.pdf', 'Budget_2024.xlsx'] },
        extractedData: { document_count: 12, sensitivity: 'confidential' },
        keywords: ['confidential', 'strategy', 'internal'],
        organization: 'Company Inc'
      },
      {
        source: 'Reddit',
        url: 'https://reddit.com/r/leaks/post/def456',
        title: 'User Account Information',
        content: 'Usernames, email addresses, and hashed passwords from user database breach.',
        classification: 'personal',
        severity: 'medium',
        confidence: 0.85,
        entities: { users: 10000, emails: ['user1@email.com'] },
        extractedData: { hash_type: 'bcrypt', breach_size: 10000 },
        keywords: ['username', 'email', 'password_hash'],
        organization: 'Company Inc'
      }
    ];

    // Create vulnerabilities for each scan
    const vulnerabilities = [];
    for (const scan of scans) {
      // Randomly assign 2-4 vulnerabilities per scan
      const numVulns = Math.floor(Math.random() * 3) + 2;
      const selectedTemplates = vulnerabilityTemplates
        .sort(() => 0.5 - Math.random())
        .slice(0, numVulns);

      for (const template of selectedTemplates) {
        vulnerabilities.push({
          scanId: scan.id,
          ...template,
          tags: ['automated_scan', scan.type],
          status: Math.random() > 0.7 ? 'confirmed' : 'open'
        });
      }
    }

    // Create leaks for darkweb and some web scans
    const leaks = [];
    for (const scan of scans) {
      if (scan.type === 'darkweb' || (scan.type === 'web' && Math.random() > 0.5)) {
        // Randomly assign 1-3 leaks per applicable scan
        const numLeaks = Math.floor(Math.random() * 3) + 1;
        const selectedTemplates = leakTemplates
          .sort(() => 0.5 - Math.random())
          .slice(0, numLeaks);

        for (const template of selectedTemplates) {
          leaks.push({
            scanId: scan.id,
            ...template,
            tags: ['automated_detection', scan.type],
            isProcessed: true,
            isVerified: Math.random() > 0.3
          });
        }
      }
    }

    // Insert vulnerabilities
    if (vulnerabilities.length > 0) {
      await Vulnerability.bulkCreate(vulnerabilities);
      console.log(`✅ Created ${vulnerabilities.length} sample vulnerabilities`);
    }

    // Insert leaks
    if (leaks.length > 0) {
      await Leak.bulkCreate(leaks);
      console.log(`✅ Created ${leaks.length} sample data leaks`);
    }

    // Summary
    const stats = {
      scans: scans.length,
      vulnerabilities: vulnerabilities.length,
      leaks: leaks.length,
      criticalVulns: vulnerabilities.filter(v => v.severity === 'critical').length,
      highSeverityLeaks: leaks.filter(l => l.severity === 'high').length
    };

    console.log('\n📊 Dashboard Data Population Summary:');
    console.log(`   Scans: ${stats.scans}`);
    console.log(`   Vulnerabilities: ${stats.vulnerabilities}`);
    console.log(`   Data Leaks: ${stats.leaks}`);
    console.log(`   Critical Vulnerabilities: ${stats.criticalVulns}`);
    console.log(`   High Severity Leaks: ${stats.highSeverityLeaks}`);
    console.log('\n✅ Dashboard data population completed successfully!');

  } catch (error) {
    console.error('❌ Error populating dashboard data:', error);
    throw error;
  }
}

// Run the script
if (require.main === module) {
  populateDashboardData()
    .then(() => {
      console.log('🎉 Script completed successfully');
      process.exit(0);
    })
    .catch((error) => {
      console.error('💥 Script failed:', error);
      process.exit(1);
    });
}

module.exports = { populateDashboardData };