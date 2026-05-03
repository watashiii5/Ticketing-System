const fs = require("fs");
const path = require("path");
const Database = require("better-sqlite3");

const dataDir = path.join(__dirname, "..", "data");
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, "ticketing.db");
const db = new Database(dbPath);

db.pragma("journal_mode = WAL");

db.exec(`
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
  );
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    company_id INTEGER NOT NULL,
    user_id INTEGER,
    assignee_id INTEGER,
    status TEXT NOT NULL DEFAULT 'open',
    priority TEXT NOT NULL DEFAULT 'medium',
    priority_confidence REAL,
    priority_reason TEXT,
    sla_due_at TEXT,
    created_at TEXT NOT NULL
  );
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    company_id INTEGER
  );
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
  );
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    original_name TEXT NOT NULL,
    stored_name TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_at TEXT NOT NULL
  );
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER,
    company_id INTEGER,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id INTEGER,
    details TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
`);

db.exec(`
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
  );
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS invites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company_id INTEGER NOT NULL,
    email TEXT,
    role TEXT NOT NULL DEFAULT 'requester',
    token_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT
  );
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT
  );
`);

ensureColumn("tickets", "company_id", "INTEGER NOT NULL DEFAULT 1");
ensureColumn("tickets", "user_id", "INTEGER");
ensureColumn("tickets", "assignee_id", "INTEGER");
ensureColumn("tickets", "priority_confidence", "REAL");
ensureColumn("tickets", "priority_reason", "TEXT");
ensureColumn("tickets", "sla_due_at", "TEXT");
ensureColumn("users", "company_id", "INTEGER");
ensureColumn("audit_logs", "company_id", "INTEGER");
ensureColumn("companies", "slug", "TEXT");
ensureColumn("companies", "brand_color", "TEXT");
ensureColumn("companies", "logo_url", "TEXT");
ensureColumn("companies", "invite_required", "INTEGER");
ensureColumn("companies", "allowed_domains", "TEXT");
ensureColumn("companies", "trial_ends_at", "TEXT");
ensureColumn("payment_requests", "paid_at", "TEXT");

const companyCount = db.prepare("SELECT COUNT(*) as count FROM companies").get().count;
if (companyCount === 0) {
  db.prepare(
    "INSERT INTO companies (name, status, plan, created_at) VALUES (?, ?, ?, ?)"
  ).run("Acme", "active", "starter", new Date().toISOString());
}

db.prepare(
  "UPDATE companies SET slug = LOWER(REPLACE(name, ' ', '-')) WHERE slug IS NULL"
).run();

const userCount = db.prepare("SELECT COUNT(*) as count FROM users").get().count;
if (userCount === 0) {
  const insertUser = db.prepare("INSERT INTO users (name, role) VALUES (?, ?)");
  const seed = db.transaction(() => {
    insertUser.run("Avery Kim", "requester");
    insertUser.run("Jordan Lee", "requester");
    insertUser.run("Riley Patel", "requester");
    insertUser.run("Morgan Diaz", "agent");
    insertUser.run("Casey Ortiz", "agent");
  });
  seed();
}

const companyId = db.prepare("SELECT id FROM companies ORDER BY id LIMIT 1").get().id;
db.prepare("UPDATE users SET company_id = ? WHERE company_id IS NULL").run(companyId);
db.prepare("UPDATE tickets SET company_id = ? WHERE company_id IS NULL").run(companyId);

const credentialCount = db
  .prepare("SELECT COUNT(*) as count FROM credentials")
  .get().count;
if (credentialCount === 0) {
  const users = db.prepare("SELECT id, name, role FROM users").all();
  const insertCred = db.prepare(
    "INSERT INTO credentials (user_id, email, password_hash) VALUES (?, ?, ?)"
  );

  const seedCreds = db.transaction(() => {
    users.forEach((user) => {
      const email = `${user.name.toLowerCase().replace(/\s+/g, ".")}@acme.test`;
      const passwordHash = "$2b$10$l.WyV73HE3EwPPxltruwxeQdDgLsb0YV4cPKUiArao3Bghh/eaedq";
      insertCred.run(user.id, email, passwordHash);
    });
  });
  seedCreds();
}

const superAdmin = db.prepare("SELECT id FROM users WHERE role = 'super_admin'").get();
if (!superAdmin) {
  const superId = db
    .prepare("INSERT INTO users (name, role, company_id) VALUES (?, ?, NULL)")
    .run("Platform Admin", "super_admin").lastInsertRowid;
  db.prepare(
    "INSERT INTO credentials (user_id, email, password_hash) VALUES (?, ?, ?)"
  ).run(
    superId,
    "admin@platform.test",
    "$2b$10$l.WyV73HE3EwPPxltruwxeQdDgLsb0YV4cPKUiArao3Bghh/eaedq"
  );
}

function ensureColumn(table, column, definition) {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all();
  const exists = columns.some((col) => col.name === column);
  if (!exists) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

db.exec(`
  CREATE TABLE IF NOT EXISTS plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    price_usd INTEGER NOT NULL,
    price_php INTEGER NOT NULL,
    icon TEXT
  );
`);

const planCount = db.prepare("SELECT COUNT(*) as count FROM plans").get().count;
if (planCount === 0) {
  const insertPlan = db.prepare("INSERT INTO plans (code, name, price_usd, price_php, icon) VALUES (?, ?, ?, ?, ?)");
  db.transaction(() => {
    insertPlan.run("starter", "Starter", 29, 1499, "🌱");
    insertPlan.run("growth", "Growth", 99, 4999, "🚀");
    insertPlan.run("enterprise", "Enterprise", 299, 14999, "🏢");
  })();
}

module.exports = db;
