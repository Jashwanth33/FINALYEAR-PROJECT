const { User } = require('./src/models');

async function createAdminUser() {
  try {
    console.log('🔄 Creating admin user...');

    const adminUser = await User.create({
      username: 'admin',
      email: 'admin@vulnsecure.com',
      password: 'admin123',
      firstName: 'Admin',
      lastName: 'User',
      role: 'admin',
      isActive: true,
      emailVerified: true
    });

    console.log('✅ Admin user created successfully:');
    console.log(`   Username: ${adminUser.username}`);
    console.log(`   Email: ${adminUser.email}`);
    console.log(`   Role: ${adminUser.role}`);
    console.log(`   ID: ${adminUser.id}`);

  } catch (error) {
    console.error('❌ Error creating admin user:', error);
    throw error;
  }
}

// Run the script
if (require.main === module) {
  createAdminUser()
    .then(() => {
      console.log('🎉 Admin user creation completed successfully');
      process.exit(0);
    })
    .catch((error) => {
      console.error('💥 Script failed:', error);
      process.exit(1);
    });
}

module.exports = { createAdminUser };