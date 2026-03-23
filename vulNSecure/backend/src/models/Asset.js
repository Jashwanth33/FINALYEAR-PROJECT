const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const Asset = sequelize.define('Asset', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  userId: {
    type: DataTypes.UUID,
    allowNull: false,
    references: { model: 'users', key: 'id' }
  },
  name: {
    type: DataTypes.STRING(255),
    allowNull: false
  },
  type: {
    type: DataTypes.ENUM('domain', 'ip', 'url', 'subnet', 'cloud', 'api', 'certificate'),
    allowNull: false
  },
  value: {
    type: DataTypes.STRING(500),
    allowNull: false
  },
  description: {
    type: DataTypes.TEXT
  },
  tags: {
    type: DataTypes.JSONB,
    defaultValue: []
  },
  metadata: {
    type: DataTypes.JSONB,
    defaultValue: {}
  },
  riskScore: {
    type: DataTypes.INTEGER,
    defaultValue: 100
  },
  lastScanDate: {
    type: DataTypes.DATE
  },
  vulnerabilityCount: {
    type: DataTypes.INTEGER,
    defaultValue: 0
  },
  status: {
    type: DataTypes.ENUM('active', 'inactive', 'monitoring', 'archived'),
    defaultValue: 'active'
  }
}, {
  tableName: 'assets'
});

module.exports = Asset;
