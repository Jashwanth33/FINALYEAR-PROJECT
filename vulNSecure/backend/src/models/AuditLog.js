const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const AuditLog = sequelize.define('AuditLog', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  userId: {
    type: DataTypes.UUID,
    allowNull: true,
    references: {
      model: 'users',
      key: 'id'
    }
  },
  action: {
    type: DataTypes.STRING(100),
    allowNull: false
  },
  resource: {
    type: DataTypes.STRING(100),
    allowNull: false
  },
  resourceId: {
    type: DataTypes.UUID
  },
  method: {
    type: DataTypes.STRING(10)
  },
  url: {
    type: DataTypes.STRING(500)
  },
  ipAddress: {
    type: DataTypes.INET
  },
  userAgent: {
    type: DataTypes.TEXT
  },
  statusCode: {
    type: DataTypes.INTEGER
  },
  requestData: {
    type: DataTypes.JSONB
  },
  responseData: {
    type: DataTypes.JSONB
  },
  errorMessage: {
    type: DataTypes.TEXT
  },
  duration: {
    type: DataTypes.INTEGER // milliseconds
  }
}, {
  tableName: 'audit_logs',
  indexes: [
    {
      fields: ['user_id']
    },
    {
      fields: ['action']
    },
    {
      fields: ['resource']
    },
    {
      fields: ['created_at']
    }
  ]
});

module.exports = AuditLog;
