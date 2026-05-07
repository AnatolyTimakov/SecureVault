const express = require('express');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { getDb } = require('../database');
const { authenticate, requireRole } = require('../middleware/auth');

const router = express.Router();

// Apply admin middleware to all routes
router.use(authenticate);
router.use(requireRole(['admin']));

// Get all users
router.get('/users', async (req, res) => {
  const db = getDb();
  
  try {
    const users = await db.all(
      `SELECT id, name, email, role, organization, two_factor_enabled, 
              created_at, last_login, is_active
       FROM users
       ORDER BY created_at DESC`
    );
    
    res.json(users);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Update user role
router.put('/users/:userId/role', [
  body('role').isIn(['user', 'manager', 'readonly', 'admin'])
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  const { userId } = req.params;
  const { role } = req.body;
  const db = getDb();
  
  try {
    // Prevent changing own role to non-admin
    if (parseInt(userId) === req.user.id && role !== 'admin') {
      return res.status(403).json({ error: 'Cannot remove your own admin privileges' });
    }
    
    await db.run(
      'UPDATE users SET role = ? WHERE id = ?',
      [role, userId]
    );
    
    const user = await db.get('SELECT email FROM users WHERE id = ?', [userId]);
    await logAudit(req.user.id, req.user.email, 'ADMIN_UPDATE_ROLE', `Changed role of ${user.email} to ${role}`, req.ip, req.headers['user-agent']);
    
    res.json({ message: 'User role updated successfully' });
  } catch (error) {
    console.error('Update role error:', error);
    res.status(500).json({ error: 'Failed to update user role' });
  }
});

// Invite user
router.post('/invite', [
  body('email').isEmail().normalizeEmail(),
  body('name').notEmpty().trim(),
  body('role').isIn(['user', 'manager', 'readonly'])
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  const { email, name, role, organization } = req.body;
  const db = getDb();
  
  try {
    const existing = await db.get('SELECT id FROM users WHERE email = ?', [email]);
    if (existing) {
      return res.status(409).json({ error: 'User already exists' });
    }
    
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7); // 7 days expiry
    
    await db.run(
      `INSERT INTO invitations (email, invited_by, role, organization, token, expires_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [email, req.user.id, role, organization || '', token, expiresAt.toISOString()]
    );
    
    await logAudit(req.user.id, req.user.email, 'ADMIN_INVITE', `Invited user: ${email}`, req.ip, req.headers['user-agent']);
    
    // In production, send email here
    res.json({ message: 'Invitation sent successfully', token: token });
  } catch (error) {
    console.error('Invite error:', error);
    res.status(500).json({ error: 'Failed to send invitation' });
  }
});

// Accept invitation
router.post('/invite/accept', [
  body('token').notEmpty(),
  body('password').isLength({ min: 12 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  const { token, password, name } = req.body;
  const db = getDb();
  
  try {
    const invitation = await db.get(
      `SELECT * FROM invitations WHERE token = ? AND expires_at > datetime('now')`,
      [token]
    );
    
    if (!invitation) {
      return res.status(400).json({ error: 'Invalid or expired invitation' });
    }
    
    const hashedPassword = await bcrypt.hash(password, parseInt(process.env.BCRYPT_ROUNDS) || 12);
    
    await db.run(
      `INSERT INTO users (name, email, password_hash, role, organization)
       VALUES (?, ?, ?, ?, ?)`,
      [name || invitation.email.split('@')[0], invitation.email, hashedPassword, invitation.role, invitation.organization]
    );
    
    await db.run('DELETE FROM invitations WHERE token = ?', [token]);
    
    res.json({ message: 'Account created successfully' });
  } catch (error) {
    console.error('Accept invite error:', error);
    res.status(500).json({ error: 'Failed to create account' });
  }
});

// Disable user
router.post('/users/:userId/disable', async (req, res) => {
  const { userId } = req.params;
  const db = getDb();
  
  try {
    if (parseInt(userId) === req.user.id) {
      return res.status(403).json({ error: 'Cannot disable your own account' });
    }
    
    await db.run('UPDATE users SET is_active = 0 WHERE id = ?', [userId]);
    
    const user = await db.get('SELECT email FROM users WHERE id = ?', [userId]);
    await logAudit(req.user.id, req.user.email, 'ADMIN_DISABLE_USER', `Disabled user: ${user.email}`, req.ip, req.headers['user-agent']);
    
    res.json({ message: 'User disabled successfully' });
  } catch (error) {
    console.error('Disable user error:', error);
    res.status(500).json({ error: 'Failed to disable user' });
  }
});

// Enable user
router.post('/users/:userId/enable', async (req, res) => {
  const { userId } = req.params;
  const db = getDb();
  
  try {
    await db.run('UPDATE users SET is_active = 1 WHERE id = ?', [userId]);
    
    const user = await db.get('SELECT email FROM users WHERE id = ?', [userId]);
    await logAudit(req.user.id, req.user.email, 'ADMIN_ENABLE_USER', `Enabled user: ${user.email}`, req.ip, req.headers['user-agent']);
    
    res.json({ message: 'User enabled successfully' });
  } catch (error) {
    console.error('Enable user error:', error);
    res.status(500).json({ error: 'Failed to enable user' });
  }
});

// Get audit logs
router.get('/audit-logs', async (req, res) => {
  const db = getDb();
  const { limit = 100, offset = 0 } = req.query;
  
  try {
    const logs = await db.all(
      `SELECT id, user_id, email, action, details, ip_address, user_agent, created_at
       FROM audit_log
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
      [parseInt(limit), parseInt(offset)]
    );
    
    const total = await db.get('SELECT COUNT(*) as count FROM audit_log');
    
    res.json({ logs, total: total.count });
  } catch (error) {
    console.error('Get audit logs error:', error);
    res.status(500).json({ error: 'Failed to fetch audit logs' });
  }
});

// Get system stats
router.get('/stats', async (req, res) => {
  const db = getDb();
  
  try {
    const totalUsers = await db.get('SELECT COUNT(*) as count FROM users');
    const totalEntries = await db.get('SELECT COUNT(*) as count FROM entries');
    const activeUsers = await db.get("SELECT COUNT(*) as count FROM users WHERE last_login > datetime('now', '-30 days')");
    const weakPasswords = await db.get('SELECT COUNT(*) as count FROM entries WHERE strength <= 2');
    
    res.json({
      totalUsers: totalUsers.count,
      totalEntries: totalEntries.count,
      activeUsers: activeUsers.count,
      weakPasswords: weakPasswords.count
    });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// Update security policies
router.post('/policies', [
  body('minPasswordLength').optional().isInt({ min: 8, max: 20 }),
  body('require2FA').optional().isBoolean(),
  body('passwordExpiryDays').optional().isInt({ min: 30, max: 365 }),
  body('preventExport').optional().isBoolean()
], async (req, res) => {
  const db = getDb();
  
  try {
    await db.run(`
      CREATE TABLE IF NOT EXISTS security_policies (
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_by INTEGER
      )
    `);
    
    const policies = req.body;
    for (const [key, value] of Object.entries(policies)) {
      await db.run(
        `INSERT INTO security_policies (key, value, updated_by) 
         VALUES (?, ?, ?) 
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = CURRENT_TIMESTAMP`,
        [key, JSON.stringify(value), req.user.id]
      );
    }
    
    await logAudit(req.user.id, req.user.email, 'ADMIN_UPDATE_POLICIES', 'Updated security policies', req.ip, req.headers['user-agent']);
    
    res.json({ message: 'Policies updated successfully' });
  } catch (error) {
    console.error('Update policies error:', error);
    res.status(500).json({ error: 'Failed to update policies' });
  }
});

// Get security policies
router.get('/policies', async (req, res) => {
  const db = getDb();
  
  try {
    const policies = await db.all('SELECT key, value FROM security_policies');
    const result = {};
    for (const policy of policies) {
      result[policy.key] = JSON.parse(policy.value);
    }
    
    res.json(result);
  } catch (error) {
    console.error('Get policies error:', error);
    res.status(500).json({ error: 'Failed to fetch policies' });
  }
});

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

module.exports = router;