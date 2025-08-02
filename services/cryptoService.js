const crypto = require('crypto');
const speakeasy = require('speakeasy');

class CryptoService {
  constructor() {
    this.algorithm = 'aes-256-gcm';
    this.rsaKeyOptions = {
      modulusLength: 2048, // RSA key size - 2048 bits for strong security
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    };
  }

  // TOTP Authentication
  generateTOTPSecret() {
    return speakeasy.generateSecret({
      name: 'Secure Banking System',
      length: 32
    });
  }

  verifyTOTP(token, secret) {
    const result = speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: token,
      window: 2 // 60s time drift
    });
  
    console.log('🔍 TOTP Verification:', {
      token,
      secret,
      result
    });
  
    return result;
  }
  

  // RSA Key Pair Generation for Digital Signatures
  generateKeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', this.rsaKeyOptions);
    return {
      privateKey: privateKey,
      publicKey: publicKey
    };
  }

  // Encrypt private key with user password using AES-256-GCM
  encryptPrivateKey(privateKey, password) {
    const salt = crypto.randomBytes(16);
    const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256'); // Increased iterations
    const iv = crypto.randomBytes(16);
    
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(Buffer.from('rsa-private-key-encryption'));
    
    let encrypted = cipher.update(privateKey, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return {
      encrypted,
      salt: salt.toString('hex'),
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex')
    };
  }

  // Decrypt private key with user password
  decryptPrivateKey(encryptedData, password) {
    try {
      const { encrypted, salt, iv, authTag } = encryptedData;
      const key = crypto.pbkdf2Sync(password, Buffer.from(salt, 'hex'), 100000, 32, 'sha256');
      
      const decipher = crypto.createDecipherGCM('aes-256-gcm', key, Buffer.from(iv, 'hex'));
      decipher.setAuthTag(Buffer.from(authTag, 'hex'));
      decipher.setAAD(Buffer.from('rsa-private-key-encryption'));
      
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      throw new Error('Failed to decrypt private key - invalid password');
    }
  }

  // Digital Signature for Transactions using RSA-PSS
  signTransaction(transactionData, privateKey) {
    try {
      const dataToSign = JSON.stringify(transactionData);
      const signature = crypto.sign('RSA-SHA256', Buffer.from(dataToSign), {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
      });
      return signature.toString('hex');
    } catch (error) {
      throw new Error('Failed to sign transaction: ' + error.message);
    }
  }

  // Verify RSA Digital Signature
  verifySignature(transactionData, signature, publicKey) {
    try {
      const dataToVerify = JSON.stringify(transactionData);
      const isValid = crypto.verify('RSA-SHA256', Buffer.from(dataToVerify), {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
      }, Buffer.from(signature, 'hex'));
      return isValid;
    } catch (error) {
      console.error('Signature verification error:', error);
      return false;
    }
  }

  // Hybrid Encryption for Messages (RSA + AES)
  encryptMessage(message, recipientPublicKey) {
    try {
      // Generate random AES key and IV for message encryption
      const aesKey = crypto.randomBytes(32); // 256-bit key
      const iv = crypto.randomBytes(16);
      
      // Encrypt the message with AES-GCM
      const cipher = crypto.createCipherGCM('aes-256-gcm', aesKey);
      cipher.setAAD(Buffer.from('secure-banking-message'));
      
      let encryptedMessage = cipher.update(message, 'utf8', 'hex');
      encryptedMessage += cipher.final('hex');
      const authTag = cipher.getAuthTag();
      
      // Encrypt the AES key with recipient's RSA public key
      const encryptedAESKey = crypto.publicEncrypt({
        key: recipientPublicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      }, aesKey);
      
      return {
        encryptedContent: encryptedMessage,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
        encryptedKey: encryptedAESKey.toString('hex')
      };
    } catch (error) {
      throw new Error('Failed to encrypt message: ' + error.message);
    }
  }

  // Decrypt Hybrid Encrypted Message
  decryptMessage(encryptedData, privateKey) {
    try {
      const { encryptedContent, iv, authTag, encryptedKey } = encryptedData;
      
      // Decrypt AES key using RSA private key
      const aesKey = crypto.privateDecrypt({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      }, Buffer.from(encryptedKey, 'hex'));
      
      // Decrypt message using AES key
      const decipher = crypto.createDecipherGCM('aes-256-gcm', aesKey);
      decipher.setAuthTag(Buffer.from(authTag, 'hex'));
      decipher.setAAD(Buffer.from('secure-banking-message'));
      
      let decrypted = decipher.update(encryptedContent, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      throw new Error('Failed to decrypt message: ' + error.message);
    }
  }

  // RSA Key Exchange for establishing shared secrets (alternative approach)
  performKeyExchange(recipientPublicKey) {
    // Generate a random shared secret
    const sharedSecret = crypto.randomBytes(32);
    
    // Encrypt shared secret with recipient's public key
    const encryptedSecret = crypto.publicEncrypt({
      key: recipientPublicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    }, sharedSecret);
    
    return {
      sharedSecret: sharedSecret.toString('hex'),
      encryptedSecret: encryptedSecret.toString('hex')
    };
  }

  // Decrypt received shared secret
  decryptSharedSecret(encryptedSecret, privateKey) {
    try {
      const decryptedSecret = crypto.privateDecrypt({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      }, Buffer.from(encryptedSecret, 'hex'));
      
      return decryptedSecret.toString('hex');
    } catch (error) {
      throw new Error('Failed to decrypt shared secret: ' + error.message);
    }
  }

  // Generate secure nonce for replay attack prevention
  generateNonce() {
    return crypto.randomBytes(16).toString('hex');
  }

  // Hash function for data integrity
  generateHash(data) {
    return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
  }

  // HMAC for additional message authentication
  generateHMAC(data, key) {
    return crypto.createHmac('sha256', key).update(JSON.stringify(data)).digest('hex');
  }

  // Verify HMAC
  verifyHMAC(data, key, expectedHmac) {
    const computedHmac = this.generateHMAC(data, key);
    return crypto.timingSafeEqual(Buffer.from(computedHmac, 'hex'), Buffer.from(expectedHmac, 'hex'));
  }

  // Threshold Signature Verification for RSA
  verifyThresholdSignatures(transaction, signatures, requiredCount) {
    let validSignatures = 0;
    const transactionData = {
      transactionId: transaction.transactionId,
      amount: transaction.amount,
      recipient: transaction.recipient,
      nonce: transaction.nonce
    };

    for (const sig of signatures) {
      try {
        // Create signature data for this specific signer
        const signatureData = {
          ...transactionData,
          signerNonce: sig.nonce
        };
        
        if (this.verifySignature(signatureData, sig.signature, sig.signer.publicKey)) {
          validSignatures++;
        }
      } catch (error) {
        console.error('Error verifying signature:', error);
        // Continue checking other signatures
      }
    }

    return validSignatures >= requiredCount;
  }

  // Additional RSA utility functions
  
  // Extract public key from private key (useful for verification)
  getPublicKeyFromPrivate(privateKey) {
    try {
      const keyObject = crypto.createPrivateKey(privateKey);
      const publicKey = crypto.createPublicKey(keyObject);
      return publicKey.export({
        type: 'spki',
        format: 'pem'
      });
    } catch (error) {
      throw new Error('Failed to extract public key: ' + error.message);
    }
  }

  // Validate RSA key pair
  validateKeyPair(privateKey, publicKey) {
    try {
      const testData = 'RSA key pair validation test';
      const signature = this.signTransaction({ test: testData }, privateKey);
      return this.verifySignature({ test: testData }, signature, publicKey);
    } catch (error) {
      return false;
    }
  }

  // Generate secure random salt for additional security
  generateSalt(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }

  // Key derivation function for additional key management
  deriveKey(password, salt, iterations = 100000, keyLength = 32) {
    return crypto.pbkdf2Sync(password, salt, iterations, keyLength, 'sha256');
  }
}

module.exports = new CryptoService();