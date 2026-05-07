const express = require('express');
const { body, validationResult } = require('express-validator');
const { getDb } = require('../database');
const { authenticate } = require('../middleware/auth');

const router = express.Router();

// Share an entry with another user
router.post('/share', authenticate, [
  body('entryId').isInt(),
  body('email').isEmail().normalizeEmail(),
  body('permission').isIn(['read', 'edit']),
  body('expiresDays').optional().isInt({ min: 1, max: 365 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  const { entryId, email, permission, expiresDays } = req.body;
  const db = getDb();
  
  try {
    // Check if user owns the entry
    const entry = await db.get(
      'SELECT id, title FROM entries WHERE id = ? AND user_id = ?',
      [entryId, req.user.id]
    );
    
    if (!entry) {
      return res.status(404).json({ error: 'Entry not found' });
    }
    
    // Find the user to share with
    const targetUser = await db.get(
      'SELECT id FROM users WHERE email = ? AND is_active = 1',
      [email]
    );
    
    if (!targetUser) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    if (targetUser.id === req.user.id) {
      return res.status(400).json({ error: 'Cannot share with yourself' });
    }
    
    // Check if already shared
    const existing = await db.get(
      'SELECT id FROM shared_entries WHERE entry_id = ? AND shared_with_id = ?',
      [entryId, targetUser.id]
    );
    
    if (existing) {
      return res.status(409).json({ error: 'Entry already shared with this user' });
    }
    
    let expiresAt = null;
    if (expiresDays) {
      expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + expiresDays);
      expiresAt = expiresAt.toISOString();
    }
    
    await db.run(
      `INSERT INTO shared_entries (entry_id, owner_id, shared_with_id, permission, expires_at)
       VALUES (?, ?, ?, ?, ?)`,
      [entryId, req.user.id, targetUser.id, permission, expiresAt]
    );
    
    await logAudit(req.user.id, req.user.email, 'SHARE_ENTRY', `Shared entry "${entry.title}" with ${email}`, req.ip, req.headers['user-agent']);
    
    res.json({ message: 'Entry shared successfully' });
  } catch (error) {
    console.error('Share error:', error);
    res.status(500).json({ error: 'Failed to share entry' });
  }
});

// Get all shared entries (incoming and outgoing)
router.get('/', authenticate, async (req, res) => {
  const db = getDb();
  
  try {
    // Entries shared by me (outgoing)
    const outgoing = await db.all(
      `SELECT s.id as share_id, e.id as entry_id, e.title, s.permission, 
              s.expires_at, s.created_at, u.name as shared_with_name, u.email as shared_with_email
       FROM shared_entries s
       JOIN entries e ON s.entry_id = e.id
       JOIN users u ON s.shared_with_id = u.id
       WHERE s.owner_id = ?`,
      [req.user.id]
    );
    
    // Entries shared with me (incoming)
    const incoming = await db.all(
      `SELECT s.id as share_id, e.id as entry_id, e.title, s.permission, 
              s.expires_at, s.created_at, u.name as owner_name, u.email as owner_email
       FROM shared_entries s
       JOIN entries e ON s.entry_id = e.id
       JOIN users u ON s.owner_id = u.id
       WHERE s.shared_with_id = ? AND (s.expires_at IS NULL OR s.expires_at > datetime('now'))`,
      [req.user.id]
    );
    
    res.json({ outgoing, incoming });
  } catch (error) {
    console.error('Get shares error:', error);
    res.status(500).json({ error: 'Failed to fetch shares' });
  }
});

// Revoke share
router.delete('/:shareId', authenticate, async (req, res) => {
  const shareId = req.params.shareId;
  const db = getDb();
  
  try {
    const share = await db.get(
      'SELECT s.*, e.title FROM shared_entries s JOIN entries e ON s.entry_id = e.id WHERE s.id = ? AND s.owner_id = ?',
      [shareId, req.user.id]
    );
    
    if (!share) {
      return res.status(404).json({ error: 'Share not found' });
    }
    
    await db.run('DELETE FROM shared_entries WHERE id = ?', [shareId]);
    
    await logAudit(req.user.id, req.user.email, 'REVOKE_SHARE', `Revoked share for entry "${share.title}"`, req.ip, req.headers['user-agent']);
    
    res.json({ message: 'Share revoked successfully' });
  } catch (error) {
    console.error('Revoke share error:', error);
    res.status(500).json({ error: 'Failed to revoke share' });
  }
});

// Update share permission
router.put('/:shareId', authenticate, [
  body('permission').isIn(['read', 'edit'])
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  const shareId = req.params.shareId;
  const { permission } = req.body;
  const db = getDb();
  
  try {
    const share = await db.get(
      'SELECT s.*, e.title FROM shared_entries s JOIN entries e ON s.entry_id = e.id WHERE s.id = ? AND s.owner_id = ?',
      [shareId, req.user.id]
    );
    
    if (!share) {
      return res.status(404).json({ error: 'Share not found' });
    }
    
    await db.run('UPDATE shared_entries SET permission = ? WHERE id = ?', [permission, shareId]);
    
    res.json({ message: 'Permission updated successfully' });
  } catch (error) {
    console.error('Update permission error:', error);
    res.status(500).json({ error: 'Failed to update permission' });
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