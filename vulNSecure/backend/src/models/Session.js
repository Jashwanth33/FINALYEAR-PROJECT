const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');
const crypto = require('crypto');

const Session = sequelize.define('Session', {
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
  tokenHash: {
    type: DataTypes.STRING(255),
    allowNull: false
  },
  ipAddress: {
    type: DataTypes.STRING(45),
    allowNull: false
  },
  userAgent: {
    type: DataTypes.STRING(500),
    allowNull: true
  },
  deviceType: {
    type: DataTypes.ENUM('desktop', 'mobile', 'tablet', 'unknown'),
    defaultValue: 'unknown'
  },
  location: {
    type: DataTypes.STRING(255),
    allowNull: true
  },
  lastActivity: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW
  },
  expiresAt: {
    type: DataTypes.DATE,
    allowNull: false
  },
  isActive: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  }
}, {
  tableName: 'sessions',
  timestamps: true
});

Session.prototype.hashToken = function(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
};

Session.prototype.isExpired = function() {
  return new Date() > new Date(this.expiresAt);
};

module.exports = Session;
