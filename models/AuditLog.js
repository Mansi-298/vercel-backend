const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  username: String,
  action: String,           // e.g., 'LOGIN', 'TX_CREATE', 'MSG_SEND'
  targetId: String,         // e.g., transactionId, messageId
  status: String,           // 'success' | 'failure'
  timestamp: { type: Date, default: Date.now }
});

module.exports = mongoose.model('AuditLog', auditLogSchema);
