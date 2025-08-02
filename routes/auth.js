const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const QRCode = require('qrcode');
const User = require('../models/User');
const cryptoService = require('../services/cryptoService');
const { logAction } = require('../services/logService');

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key';

// Register new user
router.post('/register', async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });

    if (existingUser) {
      return res.status(400).json({ 
        error: 'User already exists' 
      });
    }

    // Generate TOTP secret
    const totpSecret = cryptoService.generateTOTPSecret();
    console.log("Generated TOTP Secret (Base32):", totpSecret.base32);
console.log("TOTP otpauth_url:", totpSecret.otpauth_url);

    // Generate key pair for digital signatures
    const keyPair = cryptoService.generateKeyPair();
    const encryptedPrivateKey = cryptoService.encryptPrivateKey(
      keyPair.privateKey,
      password
    );

    // 🔐 Hash the password here
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const user = new User({
      username,
      email,
      passwordHash: hashedPassword,
      totpSecret: totpSecret.base32,
      publicKey: keyPair.publicKey,
      privateKeyEncrypted: JSON.stringify(encryptedPrivateKey),
      role: role || 'initiator'
    });

    await user.save();

    // Generate QR code for TOTP setup
    const qrCodeUrl = await QRCode.toDataURL(totpSecret.otpauth_url);

    res.status(201).json({
      message: 'User registered successfully',
      totpQR: qrCodeUrl,
      secret: totpSecret.base32,
      userId: user._id
    });

  } catch (error) {
    console.error('❌ Registration failed:', error);
    res.status(500).json({ 
      error: 'Registration failed', 
      details: error.message 
    });
  }
});


// Login with TOTP
router.post('/login', async (req, res) => {
  try {
    const { username, password, totpToken } = req.body;
    
    console.log("Login attempt:", { username, password, totpToken });

// Find user
const user = await User.findOne({ username });
if (!user) {
  console.log("❌ User not found for username:", username);
  return res.status(401).json({ error: 'Invalid credentials' });
}

// Verify password
const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
if (!isPasswordValid) {
  console.log("❌ Password mismatch for user:", username);
  console.log("Entered:", password);
  console.log("Stored hash:", user.passwordHash);
  return res.status(401).json({ error: 'Invalid credentials' });
}

// Verify TOTP token
const isTotpValid = cryptoService.verifyTOTP(totpToken, user.totpSecret);

console.log("🔐 Verifying TOTP...");
console.log("  - TOTP Token:", totpToken);
console.log("  - Stored Secret:", user.totpSecret);
console.log("  - isTotpValid:", isTotpValid);

if (!isTotpValid) {
  console.log("❌ Invalid TOTP token for user:", username);
  console.log("Entered TOTP:", totpToken);
  console.log("Expected secret:", user.totpSecret);
  return res.status(401).json({ error: 'Invalid TOTP token' });
}


    // Increment user nonce (prevent replay attacks)
    user.nonce += 1;
    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: user._id, 
        username: user.username,
        nonce: user.nonce 
      },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    await logAction({ user, action: 'LOGIN', status: 'success' });

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    res.status(500).json({ 
      error: 'Login failed', 
      details: error.message 
    });
  }
});

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

module.exports = { router, authenticateToken };