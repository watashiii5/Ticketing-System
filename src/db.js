require('dotenv').config();
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");

const dbDir = process.env.DB_DIR || path.join(__dirname, "..", "data");
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const dbPath = process.env.DB_PATH || path.join(dbDir, "ticketing.db");
const sqlite = new Database(dbPath);
sqlite.pragma("journal_mode = WAL");
sqlite.pragma("foreign_keys = ON");

const db = {
  prepare(sql) {
    const stmt = sqlite.prepare(sql);
    return {
      run(...params) {
        const result = stmt.run(...params);
        return { lastInsertRowid: result.lastInsertRowid, changes: result.changes };
      },
      get(...params) {
        return stmt.get(...params) || null;
      },
      all(...params) {
        return stmt.all(...params);
      },
    };
  },

  exec(sql) {
    sqlite.exec(sql);
  },

  query(sql, params = []) {
    return sqlite.prepare(sql).all(...params);
  },

  transaction(fn) {
    return async function (...args) {
      try {
        sqlite.exec("BEGIN");
        const result = await fn(...args);
        sqlite.exec("COMMIT");
        return result;
      } catch (e) {
        sqlite.exec("ROLLBACK");
        throw e;
      }
    };
  },
};

async function initializeDatabase() {
  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS companies (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      slug TEXT,
      brand_color TEXT,
      logo_url TEXT,
      invite_required INTEGER NOT NULL DEFAULT 0,
      allowed_domains TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      plan TEXT NOT NULL DEFAULT 'starter',
      trial_ends_at TEXT,
      created_at TEXT NOT NULL
    )
  `);

  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS tickets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      company_id INTEGER NOT NULL DEFAULT 1,
      user_id INTEGER,
      assignee_id INTEGER,
      status TEXT NOT NULL DEFAULT 'open',
      priority TEXT NOT NULL DEFAULT 'medium',
      priority_confidence REAL,
      priority_reason TEXT,
      sla_due_at TEXT,
      created_at TEXT NOT NULL
    )
  `);

  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      role TEXT NOT NULL,
      company_id INTEGER
    )
  `);

  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS credentials (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL UNIQUE,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL
    )
  `);

  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ticket_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      body TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `);

  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS attachments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ticket_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      original_name TEXT NOT NULL,
      stored_name TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      size_bytes INTEGER NOT NULL,
      created_at TEXT NOT NULL
    )
  `);

  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor_id INTEGER,
      company_id INTEGER,
      action TEXT NOT NULL,
      entity_type TEXT NOT NULL,
      entity_id INTEGER,
      details TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `);

  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS payment_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      company_id INTEGER NOT NULL,
      owner_id INTEGER NOT NULL,
      method TEXT NOT NULL,
      reference TEXT,
      amount TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      paid_at TEXT,
      created_at TEXT NOT NULL
    )
  `);

  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS invites (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      company_id INTEGER NOT NULL,
      email TEXT,
      role TEXT NOT NULL DEFAULT 'requester',
      token_hash TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used_at TEXT
    )
  `);

  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS reset_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token_hash TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used_at TEXT
    )
  `);

  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS plans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      price_usd INTEGER NOT NULL,
      price_php INTEGER NOT NULL,
      icon TEXT
    )
  `);

  // ── Seed data ────────────────────────────────────────────────
  const companyCount = sqlite.prepare("SELECT COUNT(*) as count FROM companies").get().count;
  if (companyCount === 0) {
    sqlite.prepare(
      "INSERT INTO companies (name, status, plan, created_at) VALUES (?, ?, ?, ?)"
    ).run("Acme", "active", "starter", new Date().toISOString());
  }

  sqlite.prepare(
    "UPDATE companies SET slug = LOWER(REPLACE(name, ' ', '-')) WHERE slug IS NULL"
  ).run();

  const userCount = sqlite.prepare("SELECT COUNT(*) as count FROM users").get().count;
  if (userCount === 0) {
    sqlite.prepare("INSERT INTO users (name, role) VALUES (?, ?)").run("Avery Kim", "requester");
    sqlite.prepare("INSERT INTO users (name, role) VALUES (?, ?)").run("Jordan Lee", "requester");
    sqlite.prepare("INSERT INTO users (name, role) VALUES (?, ?)").run("Riley Patel", "requester");
    sqlite.prepare("INSERT INTO users (name, role) VALUES (?, ?)").run("Morgan Diaz", "agent");
    sqlite.prepare("INSERT INTO users (name, role) VALUES (?, ?)").run("Casey Ortiz", "agent");
  }

  const firstCompany = sqlite.prepare("SELECT id FROM companies ORDER BY id LIMIT 1").get();
  if (firstCompany) {
    sqlite.prepare("UPDATE users SET company_id = ? WHERE company_id IS NULL AND role != 'super_admin'").run(firstCompany.id);
    sqlite.prepare("UPDATE tickets SET company_id = ? WHERE company_id IS NULL").run(firstCompany.id);
  }

  const credentialCount = sqlite.prepare("SELECT COUNT(*) as count FROM credentials").get().count;
  if (credentialCount === 0) {
    const users = sqlite.prepare("SELECT id, name, role FROM users").all();
    const passwordHash = "$2b$10$l.WyV73HE3EwPPxltruwxeQdDgLsb0YV4cPKUiArao3Bghh/eaedq";
    for (const user of users) {
      const email = `${user.name.toLowerCase().replace(/\s+/g, ".")}@acme.test`;
      sqlite.prepare(
        "INSERT INTO credentials (user_id, email, password_hash) VALUES (?, ?, ?)"
      ).run(user.id, email, passwordHash);
    }
  }

  const superAdmin = sqlite.prepare("SELECT id FROM users WHERE role = 'super_admin'").get();
  if (!superAdmin) {
    sqlite.prepare("DELETE FROM credentials WHERE email = ?").run("admin@platform.test");
    const result = sqlite.prepare(
      "INSERT INTO users (name, role, company_id) VALUES (?, ?, NULL)"
    ).run("Platform Admin", "super_admin");
    const superId = result.lastInsertRowid;
    sqlite.prepare(
      "INSERT INTO credentials (user_id, email, password_hash) VALUES (?, ?, ?)"
    ).run(superId, "admin@platform.test", "$2b$10$l.WyV73HE3EwPPxltruwxeQdDgLsb0YV4cPKUiArao3Bghh/eaedq");
  }

  const planCount = sqlite.prepare("SELECT COUNT(*) as count FROM plans").get().count;
  if (planCount === 0) {
    sqlite.prepare("INSERT INTO plans (code, name, price_usd, price_php, icon) VALUES (?, ?, ?, ?, ?)").run("starter", "Starter", 29, 1499, "🌱");
    sqlite.prepare("INSERT INTO plans (code, name, price_usd, price_php, icon) VALUES (?, ?, ?, ?, ?)").run("growth", "Growth", 99, 4999, "🚀");
    sqlite.prepare("INSERT INTO plans (code, name, price_usd, price_php, icon) VALUES (?, ?, ?, ?, ?)").run("enterprise", "Enterprise", 299, 14999, "🏢");
  }

  console.log("Database initialized successfully.");
}

module.exports = { db, pool: sqlite, initializeDatabase };
