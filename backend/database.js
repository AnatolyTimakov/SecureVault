const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const path = require('path');

let db;

async function initializeDatabase() {
  db = await open({
    filename: path.join(__dirname, 'vault.db'),
    driver: sqlite3.Database
  });

  // Users table
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      organization TEXT,
      two_factor_secret TEXT,
      two_factor_enabled INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_login DATETIME,
      is_active INTEGER DEFAULT 1
    )
  `);

  // Entries table (encrypted)
  await db.exec(`
    CREATE TABLE IF NOT EXISTS entries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      url TEXT,
      login TEXT,
      encrypted_password TEXT NOT NULL,
      category TEXT DEFAULT 'work',
      strength INTEGER DEFAULT 0,
      expiry_date TEXT,
      tags TEXT,
      is_favorite INTEGER DEFAULT 0,
      notes TEXT,
      totp_secret TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // Password history
  await db.exec(`
    CREATE TABLE IF NOT EXISTS password_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      entry_id INTEGER NOT NULL,
      encrypted_password TEXT NOT NULL,
      changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (entry_id) REFERENCES entries(id) ON DELETE CASCADE
    )
  `);

  // Shared entries
  await db.exec(`
    CREATE TABLE IF NOT EXISTS shared_entries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      entry_id INTEGER NOT NULL,
      owner_id INTEGER NOT NULL,
      shared_with_id INTEGER NOT NULL,
      permission TEXT DEFAULT 'read',
      expires_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (entry_id) REFERENCES entries(id) ON DELETE CASCADE,
      FOREIGN KEY (owner_id) REFERENCES users(id),
      FOREIGN KEY (shared_with_id) REFERENCES users(id)
    )
  `);

  // Audit log
  await db.exec(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      email TEXT,
      action TEXT NOT NULL,
      details TEXT,
      ip_address TEXT,
      user_agent TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  // Invitations
  await db.exec(`
    CREATE TABLE IF NOT EXISTS invitations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      invited_by INTEGER NOT NULL,
      role TEXT DEFAULT 'user',
      organization TEXT,
      token TEXT UNIQUE NOT NULL,
      expires_at DATETIME NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (invited_by) REFERENCES users(id)
    )
  `);

  // User sessions
  await db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token TEXT UNIQUE NOT NULL,
      expires_at DATETIME NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  // Create indexes
  await db.exec(`
    CREATE INDEX IF NOT EXISTS idx_entries_user_id ON entries(user_id);
    CREATE INDEX IF NOT EXISTS idx_shared_entries_shared_with ON shared_entries(shared_with_id);
    CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
  `);

  // Insert default admin user
  const bcrypt = require('bcrypt');
  const adminExists = await db.get('SELECT id FROM users WHERE email = ?', ['admin@company.com']);
  
  if (!adminExists) {
    const hashedPassword = await bcrypt.hash('Admin1234!', 12);
    await db.run(
      'INSERT INTO users (name, email, password_hash, role, organization) VALUES (?, ?, ?, ?, ?)',
      ['Александр Иванов', 'admin@company.com', hashedPassword, 'admin', 'IT Department']
    );
  }

  // Insert sample users
  const managerExists = await db.get('SELECT id FROM users WHERE email = ?', ['manager@co.com']);
  if (!managerExists) {
    const hashedPassword = await bcrypt.hash('Pass1234!', 12);
    await db.run(
      'INSERT INTO users (name, email, password_hash, role, organization) VALUES (?, ?, ?, ?, ?)',
      ['Мария Петрова', 'manager@co.com', hashedPassword, 'manager', 'IT Department']
    );
  }

  const viewerExists = await db.get('SELECT id FROM users WHERE email = ?', ['viewer@co.com']);
  if (!viewerExists) {
    const hashedPassword = await bcrypt.hash('View1234!', 12);
    await db.run(
      'INSERT INTO users (name, email, password_hash, role, organization) VALUES (?, ?, ?, ?, ?)',
      ['Сергей Смирнов', 'viewer@co.com', hashedPassword, 'readonly', 'IT Department']
    );
  }

  return db;
}

function getDb() {
  return db;
}

module.exports = { initializeDatabase, getDb };