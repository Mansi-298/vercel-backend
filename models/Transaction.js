const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
  transactionId: { 
    type: String, 
    required: true, 
    unique: true 
  },
  initiator: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  amount: { 
    type: Number, 
    required: true 
  },
  recipient: { 
    type: String, 
    required: true 
  },
  description: String,
  
  // Threshold signature requirements
  requiredSignatures: { 
    type: Number, 
    default: 3 // 3 of 5 threshold
  },
  totalSigners: { 
    type: Number, 
    default: 5 
  },
  
  // Partial signatures from different signers
  signatures: [{
    signer: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    signature: String,
    timestamp: { type: Date, default: Date.now },
    nonce: Number // Prevent replay attacks
  }],
  
  // Transaction status
  status: { 
    type: String, 
    enum: ['pending', 'approved', 'rejected', 'executed'], 
    default: 'pending' 
  },
  
  // Security features
  hash: String, // Transaction hash for integrity
  timestamp: { type: Date, default: Date.now },
  nonce: Number, // Unique nonce for replay protection
  
  // Execution details
  executedAt: Date,
  executedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}, {
  timestamps: true
});

module.exports = mongoose.model('Transaction', transactionSchema);