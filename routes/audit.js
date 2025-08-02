const express = require('express');
const AuditLog = require('../models/AuditLog');
const { authenticateToken } = require('./auth');
const router = express.Router();

router.get('/logs', authenticateToken, async (req, res) => {
  try {
    const logs = await AuditLog.find().sort({ timestamp: -1 }).limit(100);
    res.json({ logs });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch logs' });
  }
});

module.exports = router;
