const express = require('express');
const Transaction = require('../models/Transaction');
const User = require('../models/User');
const cryptoService = require('../services/cryptoService');
const { logAction } = require('../services/logService');
const { authenticateToken } = require('./auth');

const router = express.Router();

// Create new high-value transaction
router.post('/create', authenticateToken, async (req, res) => {
  try {
    const { amount, recipient, description } = req.body;
    const initiatorId = req.user.userId;

    // Generate unique transaction ID and nonce
    const transactionId = cryptoService.generateNonce();
    const nonce = Date.now(); // Timestamp-based nonce

    const transactionData = {
      transactionId,
      initiator: initiatorId,
      amount,
      recipient,
      description,
      nonce
    };

    // Generate transaction hash for integrity
    const hash = cryptoService.generateHash(transactionData);

    const transaction = new Transaction({
      ...transactionData,
      hash
    });

    await transaction.save();
    await logAction({ user: req.user, action: 'TX_CREATE', targetId: transaction.transactionId });


    res.status(201).json({
      message: 'Transaction created successfully',
      transaction: {
        id: transaction._id,
        transactionId,
        amount,
        recipient,
        status: transaction.status,
        requiredSignatures: transaction.requiredSignatures
      }
    });

  } catch (error) {
    res.status(500).json({ 
      error: 'Transaction creation failed', 
      details: error.message 
    });
  }
});

// Approve/Sign transaction (for approvers)
router.post('/approve/:transactionId', authenticateToken, async (req, res) => {
  try {
    const { transactionId } = req.params;
    const signerId = req.user.userId;

    // Find transaction
    const transaction = await Transaction.findOne({ transactionId })
      .populate('signatures.signer', 'username publicKey');
    
    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    if (transaction.status !== 'pending') {
      return res.status(400).json({ error: 'Transaction is not pending' });
    }

    // Check if user already signed
    const existingSignature = transaction.signatures.find(
      sig => sig.signer._id.toString() === signerId
    );

    if (existingSignature) {
      return res.status(400).json({ error: 'Already signed this transaction' });
    }

    // Get signer details
    const signer = await User.findById(signerId);
    if (!signer) {
      return res.status(404).json({ error: 'Signer not found' });
    }

    // Create a simple signature (in production, use proper cryptographic signing)
    const signature = `sig_${Date.now()}_${signerId}`;

    // Add signature to transaction
    transaction.signatures.push({
      signer: signerId,
      signature,
      nonce: signer.nonce + 1
    });

    // Update signer nonce
    signer.nonce += 1;
    await signer.save();

    // Check if threshold is met
    if (transaction.signatures.length >= transaction.requiredSignatures) {
      transaction.status = 'approved';
    }

    await transaction.save();
    await logAction({ user: req.user, action: 'TX_APPROVE', targetId: transaction.transactionId });

    res.json({
      message: 'Transaction signed successfully',
      signaturesCount: transaction.signatures.length,
      requiredSignatures: transaction.requiredSignatures,
      status: transaction.status
    });

  } catch (error) {
    res.status(500).json({ 
      error: 'Signing failed', 
      details: error.message 
    });
  }
});

// Sign transaction (for approvers) - Legacy endpoint
router.post('/sign/:transactionId', authenticateToken, async (req, res) => {
  try {
    const { transactionId } = req.params;
    const { password } = req.body; // Need password to decrypt private key
    const signerId = req.user.userId;

    // Find transaction
    const transaction = await Transaction.findOne({ transactionId })
      .populate('signatures.signer', 'username publicKey');
    
    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    if (transaction.status !== 'pending') {
      return res.status(400).json({ error: 'Transaction is not pending' });
    }

    // Check if user already signed
    const existingSignature = transaction.signatures.find(
      sig => sig.signer._id.toString() === signerId
    );

    if (existingSignature) {
      return res.status(400).json({ error: 'Already signed this transaction' });
    }

    // Get signer details
    const signer = await User.findById(signerId);
    if (!signer) {
      return res.status(404).json({ error: 'Signer not found' });
    }

    // Decrypt private key
    const encryptedPrivateKey = JSON.parse(signer.privateKeyEncrypted);
    const privateKey = cryptoService.decryptPrivateKey(encryptedPrivateKey, password);

    // Create signature data with nonce for replay protection
    const signatureData = {
      transactionId: transaction.transactionId,
      amount: transaction.amount,
      recipient: transaction.recipient,
      nonce: transaction.nonce,
      signerNonce: signer.nonce + 1 // Use incremented nonce
    };

    // Generate digital signature
    const signature = cryptoService.signTransaction(signatureData, privateKey);

    // Add signature to transaction
    transaction.signatures.push({
      signer: signerId,
      signature,
      nonce: signer.nonce + 1
    });

    // Update signer nonce
    signer.nonce += 1;
    await signer.save();

    // Check if threshold is met
    if (transaction.signatures.length >= transaction.requiredSignatures) {
      // Verify all signatures before approving
      const isValid = cryptoService.verifyThresholdSignatures(
        transaction,
        transaction.signatures,
        transaction.requiredSignatures
      );

      if (isValid) {
        transaction.status = 'approved';
      } else {
        transaction.status = 'rejected';
      }
    }

    await transaction.save();

    res.json({
      message: 'Transaction signed successfully',
      signaturesCount: transaction.signatures.length,
      requiredSignatures: transaction.requiredSignatures,
      status: transaction.status
    });

  } catch (error) {
    res.status(500).json({ 
      error: 'Signing failed', 
      details: error.message 
    });
  }
});

// Get transaction details
router.get('/:transactionId', authenticateToken, async (req, res) => {
  try {
    const { transactionId } = req.params;
    
    const transaction = await Transaction.findOne({ transactionId })
      .populate('initiator', 'username email')
      .populate('signatures.signer', 'username email');

    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    res.json({
      transaction: {
        id: transaction._id,
        transactionId: transaction.transactionId,
        amount: transaction.amount,
        recipient: transaction.recipient,
        description: transaction.description,
        status: transaction.status,
        initiator: transaction.initiator,
        signatures: transaction.signatures.map(sig => ({
          signer: sig.signer,
          timestamp: sig.timestamp,
          verified: true // In real app, verify each signature
        })),
        requiredSignatures: transaction.requiredSignatures,
        createdAt: transaction.createdAt
      }
    });

  } catch (error) {
    res.status(500).json({ 
      error: 'Failed to get transaction', 
      details: error.message 
    });
  }
});

// Get pending transactions for approval
router.get('/pending/list', authenticateToken, async (req, res) => {
  try {
    const transactions = await Transaction.find({ status: 'pending' })
      .populate('initiator', 'username email')
      .populate('signatures.signer', 'username')
      .sort({ createdAt: -1 });

    res.json({
      transactions: transactions.map(tx => ({
        id: tx._id,
        transactionId: tx.transactionId,
        amount: tx.amount,
        recipient: tx.recipient,
        initiator: tx.initiator,
        signaturesCount: tx.signatures.length,
        requiredSignatures: tx.requiredSignatures,
        createdAt: tx.createdAt
      }))
    });

  } catch (error) {
    res.status(500).json({ 
      error: 'Failed to get pending transactions', 
      details: error.message 
    });
  }
});

// Get transactions for approval (for approval role users)
router.get('/approvals/list', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    // Get pending transactions that user hasn't signed yet
    const transactions = await Transaction.find({ 
      status: 'pending',
      'signatures.signer': { $ne: userId } // Exclude already signed by current user
    })
      .populate('initiator', 'username email')
      .populate('signatures.signer', 'username')
      .sort({ createdAt: -1 });

    const transactionsWithSignedBy = transactions.map(tx => ({
      _id: tx._id,
      transactionId: tx.transactionId,
      amount: tx.amount,
      recipient: tx.recipient,
      description: tx.description,
      initiator: tx.initiator,
      signaturesCount: tx.signatures.length,
      requiredSignatures: tx.requiredSignatures,
      createdAt: tx.createdAt,
      signedBy: tx.signatures.map(sig => sig.signer._id.toString())
    }));

    res.json(transactionsWithSignedBy);

  } catch (error) {
    res.status(500).json({ 
      error: 'Failed to get approval transactions', 
      details: error.message 
    });
  }
});

// Get approved transactions ready for execution
router.get('/approved/list', authenticateToken, async (req, res) => {
  try {
    const transactions = await Transaction.find({ 
      status: 'approved',
      executedAt: { $exists: false }
    })
      .populate('initiator', 'username email')
      .populate('signatures.signer', 'username')
      .sort({ createdAt: -1 });

    res.json(transactions.map(tx => ({
      _id: tx._id,
      transactionId: tx.transactionId,
      amount: tx.amount,
      recipient: tx.recipient,
      description: tx.description,
      initiator: tx.initiator,
      signaturesCount: tx.signatures.length,
      requiredSignatures: tx.requiredSignatures,
      createdAt: tx.createdAt
    })));

  } catch (error) {
    res.status(500).json({ 
      error: 'Failed to get approved transactions', 
      details: error.message 
    });
  }
});

// Execute approved transaction (only by admin or initiator)
router.post('/execute/:transactionId', authenticateToken, async (req, res) => {
  try {
    const { transactionId } = req.params;
    const userId = req.user.userId;

    const transaction = await Transaction.findOne({ transactionId })
      .populate('initiator', 'username');

    if (!transaction)
      return res.status(404).json({ error: 'Transaction not found' });

    if (transaction.status !== 'approved')
      return res.status(400).json({ error: 'Transaction is not approved yet' });

    if (transaction.executedAt)
      return res.status(400).json({ error: 'Transaction already executed' });

    // Only admin or initiator can execute
    if (req.user.role !== 'admin' && transaction.initiator._id.toString() !== userId)
      return res.status(403).json({ error: 'Not authorized to execute this transaction' });

    transaction.status = 'executed';
    transaction.executedAt = new Date();
    transaction.executedBy = userId;

    await transaction.save();
    await logAction({ user: req.user, action: 'TX_EXECUTE', targetId: transaction.transactionId });


    res.json({
      message: 'Transaction executed successfully',
      transactionId: transaction.transactionId,
      executedAt: transaction.executedAt
    });

  } catch (error) {
    res.status(500).json({ error: 'Execution failed', details: error.message });
  }
});


module.exports = router;