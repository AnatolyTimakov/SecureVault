const express = require('express');
const { body, validationResult } = require('express-validator');
const { getDb } = require('../database');
const { authenticate, requireRole } = require('../middleware/auth');
const { encrypt, decrypt } = require('../encryption');

const router = express.Router();

// Get all entries for current user (including shared with them)
router.get('/', authenticate, async (req, res) => {
  const db = getDb();
  
  try {
    // Get user's own entries
    const ownEntries = await db.all(
      `SELECT id, title, url, login, category, strength, 
              expiry_date, tags, is_favorite, notes, created_at, updated_at
       FROM entries 
       WHERE user_id = ?`,
      [req.user.id]
    );
    
    // Decrypt passwords for own entries
    for (const entry of ownEntries) {
      const encryptedPass = await db.get(
        'SELECT encrypted_password FROM entries WHERE id = ?',
        [entry.id]
      );
      if (encryptedPass) {
        entry.password = decrypt(encryptedPass.encrypted_password);
      }
      
      if (entry.tags) {
        entry.tags = entry.tags.split(',');
      } else {
        entry.tags = [];
      }
    }
    
    // Get entries shared with user
    const sharedEntries = await db.all(
      `SELECT e.id, e.title, e.url, e.login, e.category, 
              s.permission, u.name as owner_name, u.email as owner_email
       FROM shared_entries s
       JOIN entries e ON s.entry_id = e.id
       JOIN users u ON s.owner_id = u.id
       WHERE s.shared_with_id = ? AND (s.expires_at IS NULL OR s.expires_at > datetime('now'))`,
      [req.user.id]
    );
    
    res.json({
      own: ownEntries,
      shared: sharedEntries
    });
  } catch (error) {
    console.error('Get entries error:', error);
    res.status(500).json({ error: 'Failed to fetch entries' });
  }
});

// Get single entry
router.get('/:id', authenticate, async (req, res) => {
  const db = getDb();
  const entryId = req.params.id;
  
  try {
    // Check if user owns this entry
    let entry = await db.get(
      'SELECT * FROM entries WHERE id = ? AND user_id = ?',
      [entryId, req.user.id]
    );
    
    let permission = 'owner';
    
    // If not owner, check if shared with user
    if (!entry) {
      const shared = await db.get(
        `SELECT s.* FROM shared_entries s
         WHERE s.entry_id = ? AND s.shared_with_id = ? 
         AND (s.expires_at IS NULL OR s.expires_at > datetime('now'))`,
        [entryId, req.user.id]
      );
      
      if (shared) {
        entry = await db.get('SELECT * FROM entries WHERE id = ?', [entryId]);
        permission = shared.permission;
      }
    }
    
    if (!entry) {
      return res.status(404).json({ error: 'Entry not found' });
    }
    
    // Decrypt password
    entry.decrypted_password = decrypt(entry.encrypted_password);
    delete entry.encrypted_password;
    
    if (entry.tags) {
      entry.tags = entry.tags.split(',');
    } else {
      entry.tags = [];
    }
    
    await logAudit(req.user.id, req.user.email, 'VIEW_ENTRY', `Viewed entry: ${entry.title}`, req.ip, req.headers['user-agent']);
    
    res.json({ entry, permission });
  } catch (error) {
    console.error('Get entry error:', error);
    res.status(500).json({ error: 'Failed to fetch entry' });
  }
});

// Create new entry
router.post('/', authenticate, [
  body('title').notEmpty().trim(),
  body('password').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  const { title, url, login, password, category, expiry_date, tags, is_favorite, notes, totp_secret } = req.body;
  const db = getDb();
  
  try {
    const encryptedPassword = encrypt(password);
    const tagsString = tags && tags.length ? tags.join(',') : '';
    const strength = calculateStrength(password);
    
    const result = await db.run(
      `INSERT INTO entries (user_id, title, url, login, encrypted_password, category, 
                           strength, expiry_date, tags, is_favorite, notes, totp_secret)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [req.user.id, title, url, login, encryptedPassword, category || 'work',
       strength, expiry_date || null, tagsString, is_favorite ? 1 : 0, notes || null, totp_secret]
    );
    
    await logAudit(req.user.id, req.user.email, 'CREATE_ENTRY', `Created entry: ${title}`, req.ip, req.headers['user-agent']);
    
    res.status(201).json({ id: result.lastID, message: 'Entry created successfully' });
  } catch (error) {
    console.error('Create entry error:', error);
    res.status(500).json({ error: 'Failed to create entry' });
  }
});

// Update entry
router.put('/:id', authenticate, [
  body('title').notEmpty().trim()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  const entryId = req.params.id;
  const { title, url, login, password, category, expiry_date, tags, is_favorite, notes, totp_secret } = req.body;
  const db = getDb();
  
  try {
    // Check ownership
    const existing = await db.get(
      'SELECT encrypted_password, title FROM entries WHERE id = ? AND user_id = ?',
      [entryId, req.user.id]
    );
    
    if (!existing) {
      return res.status(404).json({ error: 'Entry not found' });
    }
    
    // Save old password to history if changed
    if (password) {
      await db.run(
        'INSERT INTO password_history (entry_id, encrypted_password) VALUES (?, ?)',
        [entryId, existing.encrypted_password]
      );
    }
    
    const encryptedPassword = password ? encrypt(password) : existing.encrypted_password;
    const tagsString = tags && tags.length ? tags.join(',') : '';
    const strength = password ? calculateStrength(password) : null;
    
    const updates = [];
    const values = [];
    
    updates.push('title = ?'); values.push(title);
    updates.push('url = ?'); values.push(url || null);
    updates.push('login = ?'); values.push(login || null);
    updates.push('encrypted_password = ?'); values.push(encryptedPassword);
    updates.push('category = ?'); values.push(category || 'work');
    updates.push('expiry_date = ?'); values.push(expiry_date || null);
    updates.push('tags = ?'); values.push(tagsString);
    updates.push('is_favorite = ?'); values.push(is_favorite ? 1 : 0);
    updates.push('notes = ?'); values.push(notes || null);
    updates.push('totp_secret = ?'); values.push(totp_secret || null);
    updates.push('updated_at = CURRENT_TIMESTAMP');
    
    if (strength) {
      updates.push('strength = ?');
      values.push(strength);
    }
    
    values.push(entryId);
    values.push(req.user.id);
    
    await db.run(
      `UPDATE entries SET ${updates.join(', ')} WHERE id = ? AND user_id = ?`,
      values
    );
    
    await logAudit(req.user.id, req.user.email, 'UPDATE_ENTRY', `Updated entry: ${title}`, req.ip, req.headers['user-agent']);
    
    res.json({ message: 'Entry updated successfully' });
  } catch (error) {
    console.error('Update entry error:', error);
    res.status(500).json({ error: 'Failed to update entry' });
  }
});

// Delete entry
router.delete('/:id', authenticate, async (req, res) => {
  const entryId = req.params.id;
  const db = getDb();
  
  try {
    const entry = await db.get(
      'SELECT title FROM entries WHERE id = ? AND user_id = ?',
      [entryId, req.user.id]
    );
    
    if (!entry) {
      return res.status(404).json({ error: 'Entry not found' });
    }
    
    await db.run('DELETE FROM entries WHERE id = ? AND user_id = ?', [entryId, req.user.id]);
    
    await logAudit(req.user.id, req.user.email, 'DELETE_ENTRY', `Deleted entry: ${entry.title}`, req.ip, req.headers['user-agent']);
    
    res.json({ message: 'Entry deleted successfully' });
  } catch (error) {
    console.error('Delete entry error:', error);
    res.status(500).json({ error: 'Failed to delete entry' });
  }
});

// Get password history for entry
router.get('/:id/history', authenticate, async (req, res) => {
  const entryId = req.params.id;
  const db = getDb();
  
  try {
    // Verify ownership
    const entry = await db.get(
      'SELECT id FROM entries WHERE id = ? AND user_id = ?',
      [entryId, req.user.id]
    );
    
    if (!entry) {
      return res.status(404).json({ error: 'Entry not found' });
    }
    
    const history = await db.all(
      'SELECT id, changed_at FROM password_history WHERE entry_id = ? ORDER BY changed_at DESC LIMIT 10',
      [entryId]
    );
    
    // Don't return actual passwords for security
    res.json(history);
  } catch (error) {
    console.error('Get history error:', error);
    res.status(500).json({ error: 'Failed to fetch history' });
  }
});

// Copy password (log action)
router.post('/:id/copy', authenticate, async (req, res) => {
  const entryId = req.params.id;
  const db = getDb();
  
  try {
    const entry = await db.get(
      'SELECT title FROM entries WHERE id = ? AND (user_id = ? OR EXISTS (SELECT 1 FROM shared_entries WHERE entry_id = ? AND shared_with_id = ?))',
      [entryId, req.user.id, entryId, req.user.id]
    );
    
    if (entry) {
      await logAudit(req.user.id, req.user.email, 'COPY_PASSWORD', `Copied password for: ${entry.title}`, req.ip, req.headers['user-agent']);
    }
    
    res.json({ message: 'Password copy logged' });
  } catch (error) {
    console.error('Copy log error:', error);
    res.status(500).json({ error: 'Failed to log copy action' });
  }
});

// Helper functions
function calculateStrength(password) {
  let strength = 0;
  if (password.length >= 8) strength++;
  if (password.length >= 12) strength++;
  if (/[A-Z]/.test(password)) strength++;
  if (/[0-9]/.test(password)) strength++;
  if (/[^a-zA-Z0-9]/.test(password)) strength++;
  return Math.min(5, strength);
}

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

// Экспорт всех паролей пользователя
router.get('/export/:format', authenticate, async (req, res) => {
  const { format } = req.params;
  const db = getDb();
  
  try {
    // Получаем все записи пользователя
    const entries = await db.all(
      `SELECT id, title, url, login, category, strength, 
              expiry_date, tags, is_favorite, notes, created_at, updated_at
       FROM entries 
       WHERE user_id = ?`,
      [req.user.id]
    );
    
    // Расшифровываем пароли
    for (const entry of entries) {
      const encryptedPass = await db.get(
        'SELECT encrypted_password FROM entries WHERE id = ?',
        [entry.id]
      );
      if (encryptedPass) {
        entry.password = decrypt(encryptedPass.encrypted_password);
      }
      
      if (entry.tags) {
        entry.tags = entry.tags.split(',');
      } else {
        entry.tags = [];
      }
    }
    
    let fileContent;
    let filename;
    let contentType;
    
    switch (format) {
      case 'csv':
        fileContent = exportToCSV(entries);
        filename = `vault_export_${new Date().toISOString().split('T')[0]}.csv`;
        contentType = 'text/csv';
        break;
        
      case 'json':
        fileContent = exportToJSON(entries);
        filename = `vault_export_${new Date().toISOString().split('T')[0]}.json`;
        contentType = 'application/json';
        break;
        
      case 'encrypted':
        fileContent = exportToEncrypted(entries);
        filename = `vault_export_${new Date().toISOString().split('T')[0]}.vault`;
        contentType = 'application/octet-stream';
        break;
        
      default:
        return res.status(400).json({ error: 'Unsupported format' });
    }
    
    // Логируем экспорт
    await logAudit(req.user.id, req.user.email, 'EXPORT_VAULT', `Exported ${entries.length} entries as ${format}`, req.ip, req.headers['user-agent']);
    
    // Отправляем файл
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(fileContent);
    
  } catch (error) {
    console.error('Export error:', error);
    res.status(500).json({ error: 'Failed to export vault' });
  }
});

// Вспомогательные функции экспорта
function exportToCSV(entries) {
  const headers = ['Title', 'URL', 'Login', 'Password', 'Category', 'Notes', 'Tags', 'Expiry Date', 'Created', 'Updated'];
  const rows = entries.map(entry => [
    `"${entry.title.replace(/"/g, '""')}"`,
    `"${(entry.url || '').replace(/"/g, '""')}"`,
    `"${(entry.login || '').replace(/"/g, '""')}"`,
    `"${entry.password.replace(/"/g, '""')}"`,
    entry.category || '',
    `"${(entry.notes || '').replace(/"/g, '""')}"`,
    `"${(entry.tags || []).join(',').replace(/"/g, '""')}"`,
    entry.expiry_date || '',
    entry.created_at || '',
    entry.updated_at || ''
  ]);
  
  return [headers, ...rows].map(row => row.join(',')).join('\n');
}

function exportToJSON(entries) {
  const exportData = {
    exportDate: new Date().toISOString(),
    user: {
      name: currentUser?.name || req.user.name,
      email: req.user.email
    },
    totalEntries: entries.length,
    entries: entries.map(entry => ({
      title: entry.title,
      url: entry.url,
      login: entry.login,
      password: entry.password,
      category: entry.category,
      notes: entry.notes,
      tags: entry.tags,
      isFavorite: !!entry.is_favorite,
      expiryDate: entry.expiry_date,
      createdAt: entry.created_at,
      updatedAt: entry.updated_at
    }))
  };
  
  return JSON.stringify(exportData, null, 2);
}

function exportToEncrypted(entries) {
  const exportData = {
    exportDate: new Date().toISOString(),
    userEmail: req.user.email,
    entries: entries.map(entry => ({
      title: entry.title,
      url: entry.url,
      login: entry.login,
      password: entry.password,
      category: entry.category,
      notes: entry.notes,
      tags: entry.tags
    }))
  };
  
  // Шифруем весь экспорт
  const jsonString = JSON.stringify(exportData);
  return encrypt(jsonString);
}

// Импорт паролей
router.post('/import', authenticate, async (req, res) => {
  const { format, data, deduplicate } = req.body;
  const db = getDb();
  
  try {
    let importedEntries = [];
    
    // Парсим данные в зависимости от формата
    switch (format) {
      case 'csv':
        importedEntries = parseCSV(data);
        break;
      case 'json':
        importedEntries = parseJSON(data);
        break;
      case 'lastpass':
        importedEntries = parseLastPass(data);
        break;
      case 'keepass':
        importedEntries = parseKeePass(data);
        break;
      default:
        return res.status(400).json({ error: 'Unsupported format' });
    }
    
    let added = 0;
    let skipped = 0;
    let duplicates = [];
    
    // Сохраняем каждую запись
    for (const entry of importedEntries) {
      // Проверяем на дубликаты если нужно
      if (deduplicate) {
        const existing = await db.get(
          `SELECT id FROM entries 
           WHERE user_id = ? AND title = ? AND login = ?`,
          [req.user.id, entry.title, entry.login || '']
        );
        
        if (existing) {
          skipped++;
          duplicates.push(entry.title);
          continue;
        }
      }
      
      // Шифруем пароль
      const encryptedPassword = encrypt(entry.password);
      const tagsString = entry.tags ? entry.tags.join(',') : '';
      const strength = calculateStrength(entry.password);
      
      await db.run(
        `INSERT INTO entries (
          user_id, title, url, login, encrypted_password, category,
          strength, expiry_date, tags, is_favorite, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          req.user.id,
          entry.title,
          entry.url || '',
          entry.login || '',
          encryptedPassword,
          entry.category || 'work',
          strength,
          entry.expiry_date || null,
          tagsString,
          entry.is_favorite ? 1 : 0,
          entry.notes || ''
        ]
      );
      added++;
    }
    
    // Логируем импорт
    await logAudit(
      req.user.id, 
      req.user.email, 
      'IMPORT_VAULT', 
      `Imported ${added} entries from ${format}, skipped ${skipped} duplicates`,
      req.ip,
      req.headers['user-agent']
    );
    
    res.json({
      success: true,
      added,
      skipped,
      duplicates: duplicates.slice(0, 10), // Только первые 10 для отчета
      total: importedEntries.length,
      message: `Импортировано ${added} записей, пропущено ${skipped} дубликатов`
    });
    
  } catch (error) {
    console.error('Import error:', error);
    res.status(500).json({ error: 'Failed to import: ' + error.message });
  }
});

// Preview импорта
router.post('/import/preview', authenticate, async (req, res) => {
  const { format, data } = req.body;
  
  try {
    let importedEntries = [];
    
    switch (format) {
      case 'csv':
        importedEntries = parseCSV(data);
        break;
      case 'json':
        importedEntries = parseJSON(data);
        break;
      case 'lastpass':
        importedEntries = parseLastPass(data);
        break;
      case 'keepass':
        importedEntries = parseKeePass(data);
        break;
      default:
        return res.status(400).json({ error: 'Unsupported format' });
    }
    
    // Отправляем только первые 10 записей для предпросмотра
    const preview = importedEntries.slice(0, 10).map(entry => ({
      title: entry.title,
      login: entry.login,
      category: entry.category,
      hasPassword: !!entry.password,
      strength: calculateStrength(entry.password)
    }));
    
    res.json({
      total: importedEntries.length,
      preview,
      sample: importedEntries[0] || null
    });
    
  } catch (error) {
    console.error('Preview error:', error);
    res.status(500).json({ error: 'Failed to parse file: ' + error.message });
  }
});

// Парсеры для разных форматов
function parseCSV(csvData) {
  const lines = csvData.split('\n');
  const headers = lines[0].split(',').map(h => h.replace(/["']/g, '').trim().toLowerCase());
  
  const entries = [];
  for (let i = 1; i < lines.length; i++) {
    if (!lines[i].trim()) continue;
    
    // Простой парсер CSV (для реального проекта лучше использовать библиотеку)
    const values = parseCSVLine(lines[i]);
    const entry = {};
    
    headers.forEach((header, index) => {
      if (values[index]) {
        entry[header] = values[index].replace(/["']/g, '').trim();
      }
    });
    
    if (entry.title || entry.name) {
      entries.push({
        title: entry.title || entry.name || 'Imported Entry',
        url: entry.url || entry.website || '',
        login: entry.login || entry.username || entry.email || '',
        password: entry.password || entry.pass || '',
        category: entry.category || entry.group || 'work',
        notes: entry.notes || entry.comments || '',
        tags: entry.tags ? entry.tags.split(';') : []
      });
    }
  }
  
  return entries;
}

function parseCSVLine(line) {
  const result = [];
  let current = '';
  let inQuotes = false;
  
  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '"') {
      inQuotes = !inQuotes;
    } else if (char === ',' && !inQuotes) {
      result.push(current);
      current = '';
    } else {
      current += char;
    }
  }
  result.push(current);
  
  return result;
}

function parseJSON(jsonData) {
  const data = JSON.parse(jsonData);
  let entries = [];
  
  // Поддерживаем разные структуры JSON
  if (Array.isArray(data)) {
    entries = data;
  } else if (data.entries && Array.isArray(data.entries)) {
    entries = data.entries;
  } else if (data.items && Array.isArray(data.items)) {
    entries = data.items;
  } else {
    throw new Error('Unsupported JSON structure');
  }
  
  return entries.map(item => ({
    title: item.title || item.name || item.site || 'Imported',
    url: item.url || item.website || '',
    login: item.login || item.username || item.email || '',
    password: item.password || item.pass || '',
    category: item.category || item.group || item.folder || 'work',
    notes: item.notes || item.note || item.comments || '',
    tags: Array.isArray(item.tags) ? item.tags : (item.tags ? item.tags.split(',') : []),
    expiry_date: item.expiry_date || item.expires || '',
    is_favorite: item.favorite || item.starred || false
  }));
}

function parseLastPass(data) {
  // LastPass export format
  const lines = data.split('\n');
  const entries = [];
  
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    
    // LastPass CSV: url,username,password,extra,name,grouping,lastused
    const parts = parseCSVLine(line);
    if (parts.length >= 3) {
      entries.push({
        title: parts[4] || parts[0] || 'LastPass Entry',
        url: parts[0] || '',
        login: parts[1] || '',
        password: parts[2] || '',
        category: parts[5] || 'work',
        notes: parts[3] || ''
      });
    }
  }
  
  return entries;
}

function parseKeePass(data) {
  // Упрощенный парсер KeePass XML
  // Для полноценной поддержки лучше использовать xml2js библиотеку
  const entries = [];
  
  // Ищем теги <Entry> в XML
  const entryRegex = /<Entry>([\s\S]*?)<\/Entry>/g;
  let match;
  
  while ((match = entryRegex.exec(data)) !== null) {
    const entryXml = match[1];
    
    const title = extractTag(entryXml, 'Title');
    const userName = extractTag(entryXml, 'UserName');
    const password = extractTag(entryXml, 'Password');
    const url = extractTag(entryXml, 'URL');
    const notes = extractTag(entryXml, 'Notes');
    
    if (title && password) {
      entries.push({
        title: title,
        login: userName || '',
        password: password,
        url: url || '',
        notes: notes || '',
        category: 'work'
      });
    }
  }
  
  return entries;
}

function extractTag(xml, tagName) {
  const regex = new RegExp(`<${tagName}>([\\s\\S]*?)</${tagName}>`, 'i');
  const match = xml.match(regex);
  return match ? match[1].trim() : '';
}

function calculateStrength(password) {
  let strength = 0;
  if (password.length >= 8) strength++;
  if (password.length >= 12) strength++;
  if (/[A-Z]/.test(password)) strength++;
  if (/[0-9]/.test(password)) strength++;
  if (/[^a-zA-Z0-9]/.test(password)) strength++;
  return Math.min(5, strength);
}

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