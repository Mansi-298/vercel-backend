const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true, 
    unique: true 
  },
  email: { 
    type: String, 
    required: true, 
    unique: true 
  },
  passwordHash: { 
    type: String, 
    required: true 
  },
  // TOTP Authentication
  totpSecret: { 
    type: String, 
    required: true 
  },
  isVerified: { 
    type: Boolean, 
    default: false 
  },
  // Multi-sig keys for threshold signatures
  publicKey: String,
  privateKeyEncrypted: String, // Encrypted with user password
  role: {
    type: String,
    default: 'initiator',
    enum: ['initiator', 'approval']
  },
  // For preventing replay attacks
  nonce: { 
    type: Number, 
    default: 0 
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('User', userSchema);