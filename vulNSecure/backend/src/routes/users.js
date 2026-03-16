const express = require('express');
const { body, param } = require('express-validator');
const { Op } = require('sequelize');
const { User, Notification } = require('../models');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { validateRequest, asyncHandler } = require('../middleware/errorHandler');

const router = express.Router();

// @route   GET /api/users
// @desc    Get all users (admin only)
// @access  Private
router.get('/', authenticateToken, requireRole(['admin']), asyncHandler(async (req, res) => {
  const { page = 1, limit = 10, search } = req.query;

  const whereCondition = {};
  
  if (search) {
    whereCondition[Op.or] = [
      { username: { [Op.iLike]: `%${search}%` } },
      { email: { [Op.iLike]: `%${search}%` } },
      { firstName: { [Op.iLike]: `%${search}%` } },
      { lastName: { [Op.iLike]: `%${search}%` } }
    ];
  }

  const offset = (parseInt(page) - 1) * parseInt(limit);

  const { count, rows: users } = await User.findAndCountAll({
    where: whereCondition,
    attributes: { exclude: ['password', 'emailVerificationToken', 'passwordResetToken'] },
    order: [['createdAt', 'DESC']],
    limit: parseInt(limit),
    offset
  });

  res.json({
    success: true,
    data: {
      users,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: count,
        pages: Math.ceil(count / parseInt(limit))
      }
    }
  });
}));

// @route   GET /api/users/:id
// @desc    Get user by ID
// @access  Private
router.get('/:id', authenticateToken, [
  param('id').isUUID().withMessage('Invalid user ID')
], validateRequest, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;
  const { id } = req.params;

  // Users can only view their own profile unless they're admin
  if (userRole !== 'admin' && id !== userId) {
    return res.status(403).json({
      success: false,
      message: 'Access denied'
    });
  }

  const user = await User.findByPk(id, {
    attributes: { exclude: ['password', 'emailVerificationToken', 'passwordResetToken'] }
  });

  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found'
    });
  }

  res.json({
    success: true,
    data: { user }
  });
}));

// @route   PUT /api/users/:id
// @desc    Update user
// @access  Private
router.put('/:id', authenticateToken, [
  param('id').isUUID().withMessage('Invalid user ID'),
  body('firstName').optional().isLength({ min: 1, max: 50 }).withMessage('Invalid first name'),
  body('lastName').optional().isLength({ min: 1, max: 50 }).withMessage('Invalid last name'),
  body('email').optional().isEmail().withMessage('Invalid email'),
  body('role').optional().isIn(['admin', 'analyst', 'viewer']).withMessage('Invalid role'),
  body('isActive').optional().isBoolean().withMessage('isActive must be boolean')
], validateRequest, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;
  const { id } = req.params;
  const { firstName, lastName, email, role, isActive } = req.body;

  // Users can only update their own profile unless they're admin
  if (userRole !== 'admin' && id !== userId) {
    return res.status(403).json({
      success: false,
      message: 'Access denied'
    });
  }

  // Only admins can change roles and active status
  if (userRole !== 'admin' && (role !== undefined || isActive !== undefined)) {
    return res.status(403).json({
      success: false,
      message: 'Insufficient permissions'
    });
  }

  const user = await User.findByPk(id);

  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found'
    });
  }

  const updateData = {};
  if (firstName) updateData.firstName = firstName;
  if (lastName) updateData.lastName = lastName;
  if (email) updateData.email = email;
  if (role && userRole === 'admin') updateData.role = role;
  if (isActive !== undefined && userRole === 'admin') updateData.isActive = isActive;

  await user.update(updateData);

  res.json({
    success: true,
    message: 'User updated successfully',
    data: { user: user.toJSON() }
  });
}));

// @route   DELETE /api/users/:id
// @desc    Delete user (admin only)
// @access  Private
router.delete('/:id', authenticateToken, requireRole(['admin']), [
  param('id').isUUID().withMessage('Invalid user ID')
], validateRequest, asyncHandler(async (req, res) => {
  const { id } = req.params;

  // Prevent admin from deleting themselves
  if (id === req.user.id) {
    return res.status(400).json({
      success: false,
      message: 'Cannot delete your own account'
    });
  }

  const user = await User.findByPk(id);

  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found'
    });
  }

  await user.destroy();

  res.json({
    success: true,
    message: 'User deleted successfully'
  });
}));

// @route   GET /api/users/:id/notifications
// @desc    Get user notifications
// @access  Private
router.get('/:id/notifications', authenticateToken, [
  param('id').isUUID().withMessage('Invalid user ID')
], validateRequest, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;
  const { id } = req.params;
  const { unreadOnly = false } = req.query;

  // Users can only view their own notifications unless they're admin
  if (userRole !== 'admin' && id !== userId) {
    return res.status(403).json({
      success: false,
      message: 'Access denied'
    });
  }

  const whereCondition = { userId: id };
  if (unreadOnly === 'true') {
    whereCondition.isRead = false;
  }

  const notifications = await Notification.findAll({
    where: whereCondition,
    order: [['createdAt', 'DESC']],
    limit: 50
  });

  res.json({
    success: true,
    data: { notifications }
  });
}));

// @route   PUT /api/users/:id/notifications/:notificationId/read
// @desc    Mark notification as read
// @access  Private
router.put('/:id/notifications/:notificationId/read', authenticateToken, [
  param('id').isUUID().withMessage('Invalid user ID'),
  param('notificationId').isUUID().withMessage('Invalid notification ID')
], validateRequest, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;
  const { id, notificationId } = req.params;

  // Users can only update their own notifications unless they're admin
  if (userRole !== 'admin' && id !== userId) {
    return res.status(403).json({
      success: false,
      message: 'Access denied'
    });
  }

  const notification = await Notification.findOne({
    where: { id: notificationId, userId: id }
  });

  if (!notification) {
    return res.status(404).json({
      success: false,
      message: 'Notification not found'
    });
  }

  await notification.update({
    isRead: true,
    readAt: new Date()
  });

  res.json({
    success: true,
    message: 'Notification marked as read'
  });
}));

// @route   GET /api/users/:id/activity
// @desc    Get user activity
// @access  Private
router.get('/:id/activity', authenticateToken, [
  param('id').isUUID().withMessage('Invalid user ID')
], validateRequest, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;
  const { id } = req.params;

  // Users can only view their own activity unless they're admin
  if (userRole !== 'admin' && id !== userId) {
    return res.status(403).json({
      success: false,
      message: 'Access denied'
    });
  }

  // Return empty activity for now - can be extended with AuditLog model
  res.json({
    success: true,
    data: {
      activity: []
    }
  });
}));

// @route   GET /api/users/:id/sessions
// @desc    Get user sessions
// @access  Private
router.get('/:id/sessions', authenticateToken, [
  param('id').isUUID().withMessage('Invalid user ID')
], validateRequest, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;
  const { id } = req.params;

  // Users can only view their own sessions unless they're admin
  if (userRole !== 'admin' && id !== userId) {
    return res.status(403).json({
      success: false,
      message: 'Access denied'
    });
  }

  // Return empty sessions for now - can be extended with Session model
  res.json({
    success: true,
    data: {
      sessions: []
    }
  });
}));

module.exports = router;
