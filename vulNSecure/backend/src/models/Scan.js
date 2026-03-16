const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const Scan = sequelize.define('Scan', {
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
  type: {
    type: DataTypes.ENUM('network', 'web', 'darkweb'),
    allowNull: false
  },
  target: {
    type: DataTypes.STRING(255),
    allowNull: false
  },
  status: {
    type: DataTypes.ENUM('pending', 'running', 'completed', 'failed', 'cancelled'),
    defaultValue: 'pending'
  },
  progress: {
    type: DataTypes.INTEGER,
    defaultValue: 0,
    validate: {
      min: 0,
      max: 100
    }
  },
  startTime: {
    type: DataTypes.DATE
  },
  endTime: {
    type: DataTypes.DATE
  },
  configuration: {
    type: DataTypes.JSONB,
    defaultValue: {}
  },
  results: {
    type: DataTypes.JSONB,
    defaultValue: {}
  },
  summary: {
    type: DataTypes.JSONB,
    defaultValue: {}
  },
  errorMessage: {
    type: DataTypes.TEXT
  }
}, {
  tableName: 'scans'
});

module.exports = Scan;
