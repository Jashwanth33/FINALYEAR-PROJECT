const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const ScheduledScan = sequelize.define('ScheduledScan', {
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
  type: {
    type: DataTypes.ENUM('web', 'network', 'binary'),
    defaultValue: 'web'
  },
  frequency: {
    type: DataTypes.ENUM('daily', 'weekly', 'monthly'),
    allowNull: false
  },
  dayOfWeek: {
    type: DataTypes.ENUM('sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'),
    allowNull: true
  },
  time: {
    type: DataTypes.STRING(5),
    allowNull: false,
    defaultValue: '02:00'
  },
  enabled: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  },
  lastRunAt: {
    type: DataTypes.DATE,
    allowNull: true
  },
  nextRunAt: {
    type: DataTypes.DATE,
    allowNull: true
  }
}, {
  tableName: 'scheduled_scans'
});

module.exports = ScheduledScan;
