const express = require('express');
const Message = require('../models/Message');
const User = require('../models/User');
const cryptoService = require('../services/cryptoService');
const { logAction } = require('../services/logService');
const { authenticateToken } = require('./auth');

const router = express.Router();

// Send encrypted message
router.post('/send', authenticateToken, async (req, res) => {
  try {
    const { recipientId, content } = req.body;
    const senderId = req.user.userId;

    // Get recipient's public key
    const recipient = await User.findById(recipientId);
    if (!recipient) {
      return res.status(404).json({ error: 'Recipient not found' });
    }

    // Get sender for signing
    const sender = await User.findById(senderId);
    if (!sender) {
      return res.status(404).json({ error: 'Sender not found' });
    }

    // Encrypt message with recipient's public key (RSA hybrid encryption)
    const encryptedData = cryptoService.encryptMessage(content, recipient.publicKey);

    // Generate message hash and nonce
    const nonce = Date.now();
    const messageHash = cryptoService.generateHash({
      sender: senderId,
      recipient: recipientId,
      content: encryptedData.encryptedContent,
      nonce
    });

    // Create message with RSA hybrid encryption data
    const message = new Message({
      sender: senderId,
      recipient: recipientId,
      encryptedContent: encryptedData.encryptedContent,
      iv: encryptedData.iv,
      authTag: encryptedData.authTag,
      encryptedKey: encryptedData.encryptedKey, // RSA-encrypted AES key
      hash: messageHash,
      nonce
    });

    await message.save();
    await logAction({ user: req.user, action: 'MSG_SEND', targetId: message._id });


    res.status(201).json({
      message: 'Message sent successfully',
      messageId: message._id
    });

  } catch (error) {
    res.status(500).json({ 
      error: 'Failed to send message', 
      details: error.message 
    });
  }
});

// Get received messages
router.get('/received', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    const messages = await Message.find({ recipient: userId })
      .populate('sender', 'username email')
      .sort({ createdAt: -1 });

    res.json({
      messages: messages.map(msg => ({
        id: msg._id,
        sender: msg.sender,
        timestamp: msg.createdAt,
        isRead: msg.isRead,
        // Don't send encrypted content directly - will be decrypted on client
        encrypted: true
      }))
    });

  } catch (error) {
    res.status(500).json({ 
      error: 'Failed to get messages', 
      details: error.message 
    });
  }
});

// Decrypt and read specific message
router.get('/read/:messageId', authenticateToken, async (req, res) => {
  try {
    const { messageId } = req.params;
    const { password } = req.query; // Password to decrypt private key
    const userId = req.user.userId;

    const message = await Message.findById(messageId)
      .populate('sender', 'username email');

    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

    if (message.recipient.toString() !== userId) {
      return res.status(403).json({ error: 'Unauthorized to read this message' });
    }

    // Get user's private key
    const user = await User.findById(userId);
    const encryptedPrivateKey = JSON.parse(user.privateKeyEncrypted);
    const privateKey = cryptoService.decryptPrivateKey(encryptedPrivateKey, password);

    // Decrypt message using RSA hybrid decryption
    const decryptedContent = cryptoService.decryptMessage({
      encryptedContent: message.encryptedContent,
      iv: message.iv,
      authTag: message.authTag,
      encryptedKey: message.encryptedKey // RSA-encrypted AES key
    }, privateKey);

    // Mark as read
    message.isRead = true;
    await message.save();

    await logAction({ user: req.user, action: 'MSG_READ', targetId: message._id });


    res.json({
      message: {
        id: message._id,
        sender: message.sender,
        content: decryptedContent,
        timestamp: message.createdAt
      }
    });

  } catch (error) {
    res.status(500).json({ 
      error: 'Failed to decrypt message', 
      details: error.message 
    });
  }
});

module.exports = router;