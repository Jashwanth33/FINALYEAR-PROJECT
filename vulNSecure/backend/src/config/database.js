const { Sequelize } = require('sequelize');
require('dotenv').config();

// Use SQLite for development/testing if PostgreSQL is not available
const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: './database.sqlite',
  logging: process.env.NODE_ENV === 'development' ? console.log : false,
  define: {
    timestamps: true,
    underscored: true,
    freezeTableName: true
  }
});

// Override JSONB type for SQLite compatibility
const originalDefine = sequelize.define;
sequelize.define = function(modelName, attributes, options = {}) {
  // Convert JSONB to JSON for SQLite
  Object.keys(attributes).forEach(key => {
    if (attributes[key].type === Sequelize.JSONB) {
      attributes[key].type = Sequelize.JSON;
    }
  });
  
  return originalDefine.call(this, modelName, attributes, options);
};

// Note: Sequelize automatically converts iLike to LIKE for SQLite
// SQLite LIKE is case-insensitive by default for ASCII characters

module.exports = { sequelize };
