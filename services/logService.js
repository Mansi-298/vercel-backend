const AuditLog = require('../models/AuditLog');

const logAction = async ({ user, action, targetId = null, status = 'success' }) => {
  try {
    await AuditLog.create({
      userId: user?._id,
      username: user?.username,
      action,
      targetId,
      status
    });
  } catch (err) {
    console.error('Failed to log audit action:', err.message);
  }
};

module.exports = { logAction };
