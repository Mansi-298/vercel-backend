const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  sender: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  recipient: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  // End-to-end encrypted content
  encryptedContent: { 
    type: String, 
    required: true 
  },
  // Encryption metadata
  iv: String, // Initialization vector
  authTag: String, // Authentication tag for AES-GCM
  
  // Message integrity and authenticity
  signature: String, // Digital signature of sender
  hash: String, // Message hash
  
  // Replay attack prevention
  nonce: { 
    type: Number, 
    required: true 
  },
  timestamp: { 
    type: Date, 
    default: Date.now 
  },
  
  // Message status
  isRead: { 
    type: Boolean, 
    default: false 
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('Message', messageSchema);