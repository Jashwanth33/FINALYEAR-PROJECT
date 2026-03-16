const express = require('express');
const { body } = require('express-validator');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Op } = require('sequelize');
const { User } = require('../models');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { validateRequest, asyncHandler } = require('../middleware/errorHandler');
const { logger } = require('../utils/logger');

const router = express.Router();

// Generate JWT token
const generateToken = (userId) => {
  return jwt.sign(
    { userId },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRE || '7d' }
  );
};

// @route   POST /api/auth/register
// @desc    Register a new user
// @access  Public
router.post('/register', [
  body('username')
    .isLength({ min: 3, max: 50 })
    .withMessage('Username must be between 3 and 50 characters')
    .isAlphanumeric()
    .withMessage('Username must contain only alphanumeric characters'),
  body('email')
    .isEmail()
    .withMessage('Please provide a valid email')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long'),
  body('firstName')
    .isLength({ min: 1, max: 50 })
    .withMessage('First name is required'),
  body('lastName')
    .isLength({ min: 1, max: 50 })
    .withMessage('Last name is required')
], validateRequest, asyncHandler(async (req, res) => {
  const { username, email, password, firstName, lastName } = req.body;

  // Check if user already exists
  const existingUser = await User.findOne({
    where: {
      [Op.or]: [{ email }, { username }]
    }
  });

  if (existingUser) {
    return res.status(409).json({
      success: false,
      message: existingUser.email === email 
        ? 'Email already registered' 
        : 'Username already taken'
    });
  }

  // Create new user
  const user = await User.create({
    username,
    email,
    password,
    firstName,
    lastName,
    role: 'analyst' // Default role - allows creating scans
  });

  // Generate verification token
  const verificationToken = crypto.randomBytes(32).toString('hex');
  await user.update({ emailVerificationToken: verificationToken });

  const token = generateToken(user.id);

  logger.info('New user registered', {
    userId: user.id,
    username: user.username,
    email: user.email
  });

  res.status(201).json({
    success: true,
    message: 'User registered successfully',
    data: {
      user: user.toJSON(),
      token
    }
  });
}));

// @route   POST /api/auth/login
// @desc    Login user
// @access  Public
router.post('/login', [
  body('email')
    .isEmail()
    .withMessage('Please provide a valid email')
    .normalizeEmail(),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
], validateRequest, asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // Find user by email
  const user = await User.findOne({ where: { email } });

  if (!user) {
    return res.status(401).json({
      success: false,
      message: 'Invalid credentials'
    });
  }

  // Check if user is active
  if (!user.isActive) {
    return res.status(401).json({
      success: false,
      message: 'Account is deactivated'
    });
  }

  // Verify password
  const isPasswordValid = await user.comparePassword(password);

  if (!isPasswordValid) {
    return res.status(401).json({
      success: false,
      message: 'Invalid credentials'
    });
  }

  // Update last login
  await user.update({ lastLogin: new Date() });

  const token = generateToken(user.id);

  logger.info('User logged in', {
    userId: user.id,
    username: user.username,
    email: user.email,
    ip: req.ip
  });

  res.json({
    success: true,
    message: 'Login successful',
    data: {
      user: user.toJSON(),
      token
    }
  });
}));

// @route   GET /api/auth/me
// @desc    Get current user
// @access  Private
router.get('/me', authenticateToken, asyncHandler(async (req, res) => {
  res.json({
    success: true,
    data: {
      user: req.user.toJSON()
    }
  });
}));

// @route   PUT /api/auth/profile
// @desc    Update user profile
// @access  Private
router.put('/profile', authenticateToken, [
  body('firstName')
    .optional()
    .isLength({ min: 1, max: 50 })
    .withMessage('First name must be between 1 and 50 characters'),
  body('lastName')
    .optional()
    .isLength({ min: 1, max: 50 })
    .withMessage('Last name must be between 1 and 50 characters'),
  body('email')
    .optional()
    .isEmail()
    .withMessage('Please provide a valid email')
    .normalizeEmail()
], validateRequest, asyncHandler(async (req, res) => {
  const { firstName, lastName, email } = req.body;
  const userId = req.user.id;

  // Check if email is already taken by another user
  if (email && email !== req.user.email) {
    const existingUser = await User.findOne({ 
      where: { email, id: { $ne: userId } } 
    });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: 'Email already taken'
      });
    }
  }

  // Update user
  const updateData = {};
  if (firstName) updateData.firstName = firstName;
  if (lastName) updateData.lastName = lastName;
  if (email) updateData.email = email;

  await req.user.update(updateData);

  logger.info('User profile updated', {
    userId: req.user.id,
    updatedFields: Object.keys(updateData)
  });

  res.json({
    success: true,
    message: 'Profile updated successfully',
    data: {
      user: req.user.toJSON()
    }
  });
}));

// @route   PUT /api/auth/change-password
// @desc    Change user password
// @access  Private
router.put('/change-password', authenticateToken, [
  body('currentPassword')
    .notEmpty()
    .withMessage('Current password is required'),
  body('newPassword')
    .isLength({ min: 6 })
    .withMessage('New password must be at least 6 characters long')
], validateRequest, asyncHandler(async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  // Verify current password
  const isCurrentPasswordValid = await req.user.comparePassword(currentPassword);

  if (!isCurrentPasswordValid) {
    return res.status(400).json({
      success: false,
      message: 'Current password is incorrect'
    });
  }

  // Update password
  await req.user.update({ password: newPassword });

  logger.info('User password changed', {
    userId: req.user.id,
    username: req.user.username
  });

  res.json({
    success: true,
    message: 'Password changed successfully'
  });
}));

// @route   POST /api/auth/logout
// @desc    Logout user (client-side token removal)
// @access  Private
router.post('/logout', authenticateToken, asyncHandler(async (req, res) => {
  logger.info('User logged out', {
    userId: req.user.id,
    username: req.user.username
  });

  res.json({
    success: true,
    message: 'Logged out successfully'
  });
}));

module.exports = router;
