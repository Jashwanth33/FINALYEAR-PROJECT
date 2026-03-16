const { User } = require('./src/models');
const { sequelize } = require('./src/config/database');

async function upgradeViewersToAnalyst() {
  try {
    console.log('🔄 Upgrading all viewer users to analyst...');

    const [updatedCount] = await User.update(
      { role: 'analyst' },
      { 
        where: { role: 'viewer' },
        returning: true
      }
    );

    console.log(`✅ Upgraded ${updatedCount} user(s) from viewer to analyst role`);

    // List all users
    const users = await User.findAll({
      attributes: ['id', 'username', 'email', 'role'],
      order: [['createdAt', 'ASC']]
    });

    console.log('\n📋 Current users:');
    users.forEach(user => {
      console.log(`   - ${user.username} (${user.email}): ${user.role}`);
    });

  } catch (error) {
    console.error('❌ Error upgrading users:', error);
    throw error;
  }
}

// Run the script
if (require.main === module) {
  upgradeViewersToAnalyst()
    .then(() => {
      console.log('🎉 User upgrade completed successfully');
      process.exit(0);
    })
    .catch((error) => {
      console.error('💥 Script failed:', error);
      process.exit(1);
    });
}

module.exports = { upgradeViewersToAnalyst };


