const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const Notification = sequelize.define('Notification', {
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
  type: {
    type: DataTypes.ENUM('scan_complete', 'leak_detected', 'vulnerability_found', 'cve_update', 'system', 'alert'),
    allowNull: false
  },
  title: {
    type: DataTypes.STRING(255),
    allowNull: false
  },
  message: {
    type: DataTypes.TEXT,
    allowNull: false
  },
  severity: {
    type: DataTypes.ENUM('critical', 'high', 'medium', 'low', 'info'),
    defaultValue: 'info'
  },
  isRead: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  },
  readAt: {
    type: DataTypes.DATE
  },
  metadata: {
    type: DataTypes.JSONB,
    defaultValue: {}
  },
  actionUrl: {
    type: DataTypes.STRING(500)
  },
  expiresAt: {
    type: DataTypes.DATE
  }
}, {
  tableName: 'notifications'
});

module.exports = Notification;
