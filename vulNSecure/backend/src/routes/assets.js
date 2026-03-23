const express = require('express');
const { body, param, query } = require('express-validator');
const { Op } = require('sequelize');
const { Asset, Scan, Vulnerability, User } = require('../models');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { validateRequest, asyncHandler } = require('../middleware/errorHandler');
const { enumerateSubdomains, enumerateDNS, analyzeSSL } = require('../services/advancedScanner');
const { logger } = require('../utils/logger');

const router = express.Router();

router.get('/', authenticateToken, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role;
  const { type, status, search, page = 1, limit = 20 } = req.query;

  const where = userRole === 'admin' ? {} : { userId };
  if (type) where.type = type;
  if (status) where.status = status;
  if (search) {
    where[Op.or] = [
      { name: { [Op.iLike]: `%${search}%` } },
      { value: { [Op.iLike]: `%${search}%` } }
    ];
  }

  const { count, rows: assets } = await Asset.findAndCountAll({
    where,
    include: [{ model: User, as: 'user', attributes: ['username', 'firstName', 'lastName'] }],
    order: [['createdAt', 'DESC']],
    limit: parseInt(limit),
    offset: (parseInt(page) - 1) * parseInt(limit)
  });

  res.json({
    success: true,
    data: { assets, pagination: { page: parseInt(page), limit: parseInt(limit), total: count } }
  });
}));

router.get('/:id', authenticateToken, asyncHandler(async (req, res) => {
  const { id } = req.params;
  const asset = await Asset.findByPk(id, {
    include: [{ model: User, as: 'user', attributes: ['username', 'firstName', 'lastName'] }]
  });

  if (!asset) {
    return res.status(404).json({ success: false, message: 'Asset not found' });
  }

  if (req.user.role !== 'admin' && asset.userId !== req.user.id) {
    return res.status(403).json({ success: false, message: 'Access denied' });
  }

  res.json({ success: true, data: asset });
}));

router.post('/', authenticateToken, requireRole(['admin', 'analyst']), [
  body('name').notEmpty().withMessage('Name is required'),
  body('type').isIn(['domain', 'ip', 'url', 'subnet', 'cloud', 'api', 'certificate']).withMessage('Invalid type'),
  body('value').notEmpty().withMessage('Value is required')
], validateRequest, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const { name, type, value, description, tags = [] } = req.body;

  const asset = await Asset.create({ userId, name, type, value, description, tags });

  logger.info('Asset created', { assetId: asset.id, userId, type });
  res.status(201).json({ success: true, data: asset });
}));

router.put('/:id', authenticateToken, requireRole(['admin', 'analyst']), asyncHandler(async (req, res) => {
  const { id } = req.params;
  const asset = await Asset.findByPk(id);

  if (!asset) {
    return res.status(404).json({ success: false, message: 'Asset not found' });
  }

  if (req.user.role !== 'admin' && asset.userId !== req.user.id) {
    return res.status(403).json({ success: false, message: 'Access denied' });
  }

  const { name, description, tags, status, metadata } = req.body;
  await asset.update({ name, description, tags, status, metadata });

  res.json({ success: true, data: asset });
}));

router.delete('/:id', authenticateToken, requireRole(['admin']), asyncHandler(async (req, res) => {
  const { id } = req.params;
  const asset = await Asset.findByPk(id);

  if (!asset) {
    return res.status(404).json({ success: false, message: 'Asset not found' });
  }

  await asset.destroy();
  res.json({ success: true, message: 'Asset deleted' });
}));

router.post('/:id/discover', authenticateToken, requireRole(['admin', 'analyst']), asyncHandler(async (req, res) => {
  const { id } = req.params;
  const asset = await Asset.findByPk(id);

  if (!asset) {
    return res.status(404).json({ success: false, message: 'Asset not found' });
  }

  const discovery = { subdomains: [], dns: {}, ssl: null, ports: [] };

  if (asset.type === 'domain') {
    discovery.subdomains = await enumerateSubdomains(asset.value);
    discovery.dns = await enumerateDNS(asset.value);
  }

  if (asset.type === 'certificate' || (asset.type === 'domain' && asset.value.startsWith('https'))) {
    discovery.ssl = await analyzeSSL(asset.value.startsWith('http') ? asset.value : `https://${asset.value}`);
  }

  await asset.update({
    metadata: { ...asset.metadata, lastDiscovery: discovery },
    lastScanDate: new Date()
  });

  res.json({ success: true, data: discovery });
}));

router.post('/:id/scan', authenticateToken, requireRole(['admin', 'analyst']), asyncHandler(async (req, res) => {
  const { id } = req.params;
  const asset = await Asset.findByPk(id);

  if (!asset) {
    return res.status(404).json({ success: false, message: 'Asset not found' });
  }

  const scan = await Scan.create({
    userId: req.user.id,
    name: `Scan - ${asset.name}`,
    type: asset.type === 'domain' || asset.type === 'url' ? 'web' : 'network',
    target: asset.value,
    status: 'pending'
  });

  await asset.update({ lastScanDate: new Date() });

  res.status(201).json({ success: true, data: scan });
}));

module.exports = router;
