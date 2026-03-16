const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const CVE = sequelize.define('CVE', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  cveId: {
    type: DataTypes.STRING(20),
    allowNull: false,
    unique: true
  },
  description: {
    type: DataTypes.TEXT,
    allowNull: false
  },
  severity: {
    type: DataTypes.ENUM('critical', 'high', 'medium', 'low'),
    allowNull: false
  },
  cvssScore: {
    type: DataTypes.DECIMAL(3, 1),
    validate: {
      min: 0,
      max: 10
    }
  },
  cvssVector: {
    type: DataTypes.STRING(100)
  },
  cvssVersion: {
    type: DataTypes.STRING(5),
    defaultValue: '3.1'
  },
  publishedDate: {
    type: DataTypes.DATE
  },
  lastModifiedDate: {
    type: DataTypes.DATE
  },
  cpe: {
    type: DataTypes.JSONB,
    defaultValue: []
  },
  cwe: {
    type: DataTypes.JSONB,
    defaultValue: []
  },
  references: {
    type: DataTypes.JSONB,
    defaultValue: []
  },
  configurations: {
    type: DataTypes.JSONB,
    defaultValue: []
  },
  rawData: {
    type: DataTypes.JSONB,
    defaultValue: {}
  },
  isActive: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  }
}, {
  tableName: 'cves',
  indexes: [
    {
      fields: ['cve_id']
    },
    {
      fields: ['severity']
    },
    {
      fields: ['cvss_score']
    },
    {
      fields: ['published_date']
    }
  ]
});

module.exports = CVE;
