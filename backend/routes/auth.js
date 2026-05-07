const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { body, validationResult } = require('express-validator');
const { getDb } = require('../database');
const { authenticate } = require('../middleware/auth');

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key_change_me';

// Login
router.post('/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password, twoFactorCode } = req.body;
  const db = getDb();

  try {
    const user = await db.get(
      'SELECT * FROM users WHERE email = ? AND is_active = 1',
      [email]
    );

    if (!user) {
      await logAudit(null, email, 'LOGIN_FAILED', 'User not found', req.ip, req.headers['user-agent']);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      await logAudit(user.id, email, 'LOGIN_FAILED', 'Invalid password', req.ip, req.headers['user-agent']);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check 2FA if enabled
    if (user.two_factor_enabled) {
      if (!twoFactorCode) {
        return res.status(200).json({ requiresTwoFactor: true });
      }
      
      const verified = speakeasy.totp.verify({
        secret: user.two_factor_secret,
        encoding: 'base32',
        token: twoFactorCode
      });
      
      if (!verified) {
        await logAudit(user.id, email, 'LOGIN_FAILED', 'Invalid 2FA code', req.ip, req.headers['user-agent']);
        return res.status(401).json({ error: 'Invalid 2FA code' });
      }
    }

    // Update last login
    await db.run(
      'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
      [user.id]
    );

    // Generate JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    await logAudit(user.id, email, 'LOGIN_SUCCESS', 'User logged in', req.ip, req.headers['user-agent']);

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        organization: user.organization,
        twoFactorEnabled: !!user.two_factor_enabled
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Register
router.post('/register', [
  body('name').notEmpty().trim(),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 12 }),
  body('role').optional().isIn(['user', 'manager', 'readonly']),
  body('organization').optional().trim()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { name, email, password, role, organization } = req.body;
  const db = getDb();

  try {
    const existing = await db.get('SELECT id FROM users WHERE email = ?', [email]);
    if (existing) {
      return res.status(409).json({ error: 'User with this email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, parseInt(process.env.BCRYPT_ROUNDS) || 12);
    
    await db.run(
      'INSERT INTO users (name, email, password_hash, role, organization) VALUES (?, ?, ?, ?, ?)',
      [name, email, hashedPassword, role || 'user', organization || '']
    );

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Setup 2FA
router.post('/2fa/setup', authenticate, async (req, res) => {
  const db = getDb();
  
  try {
    const secret = speakeasy.generateSecret({ length: 20, name: `SecureVault (${req.user.email})` });
    
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
    
    // Store secret temporarily (will be confirmed)
    req.session.temp2FASecret = secret.base32;
    
    res.json({
      secret: secret.base32,
      qrCode: qrCodeUrl,
      otpauthUrl: secret.otpauth_url
    });
  } catch (error) {
    console.error('2FA setup error:', error);
    res.status(500).json({ error: 'Failed to setup 2FA' });
  }
});

// Verify and enable 2FA
router.post('/2fa/verify', authenticate, [
  body('code').isLength({ min: 6, max: 6 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { code, secret } = req.body;
  const db = getDb();

  try {
    const verified = speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: code
    });

    if (!verified) {
      return res.status(400).json({ error: 'Invalid verification code' });
    }

    await db.run(
      'UPDATE users SET two_factor_secret = ?, two_factor_enabled = 1 WHERE id = ?',
      [secret, req.user.id]
    );

    res.json({ message: '2FA enabled successfully', recoveryCodes: generateRecoveryCodes() });
  } catch (error) {
    console.error('2FA verify error:', error);
    res.status(500).json({ error: 'Failed to verify 2FA' });
  }
});

// Disable 2FA
router.post('/2fa/disable', authenticate, [
  body('password').notEmpty()
], async (req, res) => {
  const { password } = req.body;
  const db = getDb();

  try {
    const user = await db.get('SELECT password_hash FROM users WHERE id = ?', [req.user.id]);
    
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    await db.run(
      'UPDATE users SET two_factor_secret = NULL, two_factor_enabled = 0 WHERE id = ?',
      [req.user.id]
    );

    res.json({ message: '2FA disabled successfully' });
  } catch (error) {
    console.error('2FA disable error:', error);
    res.status(500).json({ error: 'Failed to disable 2FA' });
  }
});

// Change master password
router.post('/change-password', authenticate, [
  body('currentPassword').notEmpty(),
  body('newPassword').isLength({ min: 12 })
], async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const db = getDb();

  try {
    const user = await db.get('SELECT password_hash FROM users WHERE id = ?', [req.user.id]);
    
    const validPassword = await bcrypt.compare(currentPassword, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, parseInt(process.env.BCRYPT_ROUNDS) || 12);
    
    await db.run(
      'UPDATE users SET password_hash = ? WHERE id = ?',
      [hashedPassword, req.user.id]
    );

    await logAudit(req.user.id, req.user.email, 'PASSWORD_CHANGED', 'Master password changed', req.ip, req.headers['user-agent']);

    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('Password change error:', error);
    res.status(500).json({ error: 'Failed to change password' });
  }
});

// Logout
router.post('/logout', authenticate, async (req, res) => {
  await logAudit(req.user.id, req.user.email, 'LOGOUT', 'User logged out', req.ip, req.headers['user-agent']);
  res.json({ message: 'Logged out successfully' });
});

// Helper functions
async function logAudit(userId, email, action, details, ip, userAgent) {
  const db = getDb();
  try {
    await db.run(
      'INSERT INTO audit_log (user_id, email, action, details, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)',
      [userId, email, action, details, ip, userAgent]
    );
  } catch (error) {
    console.error('Audit log error:', error);
  }
}

function generateRecoveryCodes() {
  const codes = [];
  for (let i = 0; i < 8; i++) {
    codes.push(Math.random().toString(36).substring(2, 10).toUpperCase());
  }
  return codes;
}

module.exports = router;