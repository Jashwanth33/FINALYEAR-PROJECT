const User = require('./User');
const Scan = require('./Scan');
const Vulnerability = require('./Vulnerability');
const Leak = require('./Leak');
const CVE = require('./CVE');
const Report = require('./Report');
const Notification = require('./Notification');
const AuditLog = require('./AuditLog');
const Schedule = require('./Schedule');
const Asset = require('./Asset');
const ScheduledScan = require('./ScheduledScan');

// User associations
User.hasMany(Scan, { foreignKey: 'userId', as: 'scans' });
User.hasMany(Report, { foreignKey: 'userId', as: 'reports' });
User.hasMany(Notification, { foreignKey: 'userId', as: 'notifications' });
User.hasMany(AuditLog, { foreignKey: 'userId', as: 'auditLogs' });
User.hasMany(ScheduledScan, { foreignKey: 'userId', as: 'scheduledScans' });

// Scan associations
Scan.belongsTo(User, { foreignKey: 'userId', as: 'user' });
Scan.hasMany(Vulnerability, { foreignKey: 'scanId', as: 'vulnerabilities' });
Scan.hasMany(Leak, { foreignKey: 'scanId', as: 'leaks' });
Scan.hasMany(Report, { foreignKey: 'scanId', as: 'reports' });

// Vulnerability associations
Vulnerability.belongsTo(Scan, { foreignKey: 'scanId', as: 'scan' });
Vulnerability.belongsTo(CVE, { foreignKey: 'cveId', targetKey: 'cveId', as: 'cve' });

// Leak associations
Leak.belongsTo(Scan, { foreignKey: 'scanId', as: 'scan' });

// Report associations
Report.belongsTo(User, { foreignKey: 'userId', as: 'user' });
Report.belongsTo(Scan, { foreignKey: 'scanId', as: 'scan' });

// Notification associations
Notification.belongsTo(User, { foreignKey: 'userId', as: 'user' });

// AuditLog associations
AuditLog.belongsTo(User, { foreignKey: 'userId', as: 'user' });

// Schedule associations
User.hasMany(Schedule, { foreignKey: 'userId', as: 'schedules' });
Schedule.belongsTo(User, { foreignKey: 'userId', as: 'user' });

// Asset associations
User.hasMany(Asset, { foreignKey: 'userId', as: 'assets' });
Asset.belongsTo(User, { foreignKey: 'userId', as: 'user' });

module.exports = {
  User,
  Scan,
  Vulnerability,
  Leak,
  CVE,
  Report,
  Notification,
  AuditLog,
  Schedule,
  Asset,
  ScheduledScan
};
