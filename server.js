const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
require('dotenv').config();

// Define PORT first
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://vercel-frontend-silk.vercel.app'
  ],
  credentials: true
}));
app.use(express.json());

// Import routes
const { router: authRoutes } = require('./routes/auth');
const transactionRoutes = require('./routes/transactions');
const messagingRoutes = require('./routes/messaging');
const auditRoutes = require('./routes/audit');

// Test endpoint
app.get('/api/test', (req, res) => {
  res.json({ message: 'Backend server is running!' });
});

app.use('/api/auth', authRoutes);
app.use('/api/transactions', transactionRoutes);
app.use('/api/messaging', messagingRoutes);
app.use('/api/audit', auditRoutes);

app.get('/', (req, res) => {
  res.send('✅ Backend is alive');
});



// MongoDB Connection
mongoose.connect(process.env.MONGO_URL || 'mongodb://localhost:27017/secure_banking')
  .then(() => {
    console.log('✅ MongoDB connected successfully');
  })
  .catch((err) => {
    console.error('❌ MongoDB connection error:', err);
  });

// For Vercel, export the app instead of starting server
module.exports = app;