const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const Schedule = sequelize.define('Schedule', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  userId: {
    type: DataTypes.UUID,
    allowNull: false,
    references: {
      model: 'users',
      key: 'id'
    }
  },
  name: {
    type: DataTypes.STRING(100),
    allowNull: false
  },
  target: {
    type: DataTypes.STRING(255),
    allowNull: false
  },
  scanType: {
    type: DataTypes.ENUM('network', 'web', 'darkweb'),
    allowNull: false,
    defaultValue: 'web'
  },
  cronExpression: {
    type: DataTypes.STRING(50),
    allowNull: false
  },
  isActive: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  },
  lastRun: {
    type: DataTypes.DATE
  },
  nextRun: {
    type: DataTypes.DATE
  },
  configuration: {
    type: DataTypes.JSONB,
    defaultValue: {}
  },
  notificationEmail: {
    type: DataTypes.STRING(255)
  },
  notifyOnVulnerability: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  }
}, {
  tableName: 'schedules'
});

module.exports = Schedule;
