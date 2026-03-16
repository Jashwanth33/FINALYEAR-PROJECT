const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const Report = sequelize.define('Report', {
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
  scanId: {
    type: DataTypes.UUID,
    allowNull: true,
    references: {
      model: 'scans',
      key: 'id'
    }
  },
  title: {
    type: DataTypes.STRING(255),
    allowNull: false
  },
  type: {
    type: DataTypes.ENUM('scan', 'leak', 'combined', 'custom'),
    allowNull: false
  },
  format: {
    type: DataTypes.ENUM('pdf', 'html', 'json', 'csv'),
    defaultValue: 'pdf'
  },
  status: {
    type: DataTypes.ENUM('pending', 'generating', 'completed', 'failed'),
    defaultValue: 'pending'
  },
  filePath: {
    type: DataTypes.STRING(500)
  },
  fileName: {
    type: DataTypes.STRING(255)
  },
  fileSize: {
    type: DataTypes.BIGINT
  },
  configuration: {
    type: DataTypes.JSONB,
    defaultValue: {}
  },
  summary: {
    type: DataTypes.JSONB,
    defaultValue: {}
  },
  errorMessage: {
    type: DataTypes.TEXT
  },
  isPublic: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  },
  expiresAt: {
    type: DataTypes.DATE
  }
}, {
  tableName: 'reports'
});

module.exports = Report;
