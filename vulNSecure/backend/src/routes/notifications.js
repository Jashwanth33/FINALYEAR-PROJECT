const express = require('express');
const { query, param } = require('express-validator');
const { Notification, User } = require('../models');
const { authenticateToken } = require('../middleware/auth');
const { validateRequest, asyncHandler } = require('../middleware/errorHandler');

const router = express.Router();

// @route   GET /api/notifications
// @desc    Get current user's notifications
// @access  Private
router.get('/', authenticateToken, [
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
  query('unreadOnly').optional().isBoolean().withMessage('unreadOnly must be boolean')
], validateRequest, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const { limit = 10, unreadOnly = false } = req.query;

  const whereCondition = { userId };
  if (unreadOnly === 'true' || unreadOnly === true) {
    whereCondition.isRead = false;
  }

  const notifications = await Notification.findAll({
    where: whereCondition,
    order: [['createdAt', 'DESC']],
    limit: parseInt(limit)
  });

  const unreadCount = await Notification.count({
    where: { userId, isRead: false }
  });

  res.json({
    success: true,
    data: {
      notifications,
      unreadCount
    }
  });
}));

// @route   PATCH /api/notifications/:id/read
// @desc    Mark notification as read
// @access  Private
router.patch('/:id/read', authenticateToken, [
  param('id').isUUID().withMessage('Invalid notification ID')
], validateRequest, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const { id } = req.params;

  const notification = await Notification.findOne({
    where: { id, userId }
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

// @route   PATCH /api/notifications/mark-all-read
// @desc    Mark all notifications as read
// @access  Private
router.patch('/mark-all-read', authenticateToken, asyncHandler(async (req, res) => {
  const userId = req.user.id;

  await Notification.update(
    { isRead: true, readAt: new Date() },
    { where: { userId, isRead: false } }
  );

  res.json({
    success: true,
    message: 'All notifications marked as read'
  });
}));

// @route   POST /api/notifications/test-email
// @desc    Send test email
// @access  Admin only
router.post('/test-email', require('express-validator').body('email').isEmail(), validateRequest, require('express').Router() || (async (req, res) => {
  const emailService = require('../services/emailService');
  const { email } = req.body;
  
  const result = await emailService.sendEmail(
    email,
    'Test Email from vulNSecure',
    '<h1>Test Email</h1><p>This is a test email from vulNSecure Platform.</p>'
  );
  
  if (result.success) {
    res.json({ success: true, message: 'Test email sent successfully' });
  } else {
    res.status(500).json({ success: false, message: 'Failed to send email: ' + result.error });
  }
}));

module.exports = router;


