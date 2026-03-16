const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const Leak = sequelize.define('Leak', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  scanId: {
    type: DataTypes.UUID,
    allowNull: false,
    references: {
      model: 'scans',
      key: 'id'
    }
  },
  source: {
    type: DataTypes.STRING(100),
    allowNull: false
  },
  url: {
    type: DataTypes.STRING(500),
    allowNull: false
  },
  title: {
    type: DataTypes.STRING(255),
    allowNull: false
  },
  content: {
    type: DataTypes.TEXT,
    allowNull: false
  },
  classification: {
    type: DataTypes.ENUM('pii', 'credentials', 'financial', 'personal', 'corporate', 'other'),
    allowNull: false
  },
  severity: {
    type: DataTypes.ENUM('critical', 'high', 'medium', 'low'),
    allowNull: false
  },
  confidence: {
    type: DataTypes.DECIMAL(3, 2),
    validate: {
      min: 0,
      max: 1
    }
  },
  entities: {
    type: DataTypes.JSONB,
    defaultValue: {}
  },
  extractedData: {
    type: DataTypes.JSONB,
    defaultValue: {}
  },
  keywords: {
    type: DataTypes.JSONB,
    defaultValue: []
  },
  language: {
    type: DataTypes.STRING(10),
    defaultValue: 'en'
  },
  country: {
    type: DataTypes.STRING(2)
  },
  organization: {
    type: DataTypes.STRING(100)
  },
  isProcessed: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  },
  isVerified: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  },
  verificationNotes: {
    type: DataTypes.TEXT
  },
  tags: {
    type: DataTypes.JSONB,
    defaultValue: []
  }
}, {
  tableName: 'leaks'
});

module.exports = Leak;
