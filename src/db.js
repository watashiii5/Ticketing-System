const { Pool } = require("pg");
const bcrypt = require("bcryptjs");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes("localhost")
    ? { rejectUnauthorized: false }
    : false,
});

// ── Compatibility wrapper ────────────────────────────────────────
// Mimics the better-sqlite3 synchronous API so the rest of the
// codebase keeps working with minimal changes.  All methods are
// now async but the call-sites will `await` them.
// ─────────────────────────────────────────────────────────────────

function convertPlaceholders(sql) {
  let idx = 0;
  return sql.replace(/\?/g, () => `$${++idx}`);
}

const db = {
  prepare(sql) {
    const pgSql = convertPlaceholders(sql);
    return {
      async run(...params) {
        const result = await pool.query(pgSql, params);
        return { lastInsertRowid: result.rows[0]?.id, changes: result.rowCount };
      },
      async get(...params) {
        const result = await pool.query(pgSql, params);
        return result.rows[0] || null;
      },
      async all(...params) {
        const result = await pool.query(pgSql, params);
        return result.rows;
      },
    };
  },

  async exec(sql) {
    await pool.query(sql);
  },

  async query(sql, params = []) {
    const result = await pool.query(sql, params);
    return result;
  },

  // Transaction helper
  transaction(fn) {
    return async function (...args) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await fn(...args);
        await client.query("COMMIT");
      } catch (e) {
        await client.query("ROLLBACK");
        throw e;
      } finally {
        client.release();
      }
    };
  },
};

// ── INSERT ... RETURNING id wrapper ──────────────────────────────
// SQLite returns lastInsertRowid; Postgres needs RETURNING id.
// We override `run` for INSERT statements to append RETURNING id.
const originalPrepare = db.prepare.bind(db);
db.prepare = function (sql) {
  const isInsert = sql.trim().toUpperCase().startsWith("INSERT");
  const pgSql = convertPlaceholders(sql);
  const pgSqlReturning = isInsert && !pgSql.toUpperCase().includes("RETURNING")
    ? pgSql + " RETURNING id"
    : pgSql;

  return {
    async run(...params) {
      const result = await pool.query(isInsert ? pgSqlReturning : pgSql, params);
      return {
        lastInsertRowid: result.rows[0]?.id ?? null,
        changes: result.rowCount,
      };
    },
    async get(...params) {
      const result = await pool.query(pgSql, params);
      return result.rows[0] || null;
    },
    async all(...params) {
      const result = await pool.query(pgSql, params);
      return result.rows;
    },
  };
};

// ── Schema creation ──────────────────────────────────────────────
async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS companies (
      id SERIAL PRIMARY KEY,
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

  await pool.query(`
    CREATE TABLE IF NOT EXISTS tickets (
      id SERIAL PRIMARY KEY,
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
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      role TEXT NOT NULL,
      company_id INTEGER
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS credentials (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL UNIQUE,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS comments (
      id SERIAL PRIMARY KEY,
      ticket_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      body TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS attachments (
      id SERIAL PRIMARY KEY,
      ticket_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      original_name TEXT NOT NULL,
      stored_name TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      size_bytes INTEGER NOT NULL,
      created_at TEXT NOT NULL
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id SERIAL PRIMARY KEY,
      actor_id INTEGER,
      company_id INTEGER,
      action TEXT NOT NULL,
      entity_type TEXT NOT NULL,
      entity_id INTEGER,
      details TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS payment_requests (
      id SERIAL PRIMARY KEY,
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

  await pool.query(`
    CREATE TABLE IF NOT EXISTS invites (
      id SERIAL PRIMARY KEY,
      company_id INTEGER NOT NULL,
      email TEXT,
      role TEXT NOT NULL DEFAULT 'requester',
      token_hash TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used_at TEXT
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS reset_tokens (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      token_hash TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used_at TEXT
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS plans (
      id SERIAL PRIMARY KEY,
      code TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      price_usd INTEGER NOT NULL,
      price_php INTEGER NOT NULL,
      icon TEXT
    );
  `);

  // ── Seed data ────────────────────────────────────────────────
  const companyCount = (await pool.query("SELECT COUNT(*) as count FROM companies")).rows[0].count;
  if (parseInt(companyCount) === 0) {
    await pool.query(
      "INSERT INTO companies (name, status, plan, created_at) VALUES ($1, $2, $3, $4)",
      ["Acme", "active", "starter", new Date().toISOString()]
    );
  }

  await pool.query(
    "UPDATE companies SET slug = LOWER(REPLACE(name, ' ', '-')) WHERE slug IS NULL"
  );

  const userCount = (await pool.query("SELECT COUNT(*) as count FROM users")).rows[0].count;
  if (parseInt(userCount) === 0) {
    await pool.query("INSERT INTO users (name, role) VALUES ($1, $2)", ["Avery Kim", "requester"]);
    await pool.query("INSERT INTO users (name, role) VALUES ($1, $2)", ["Jordan Lee", "requester"]);
    await pool.query("INSERT INTO users (name, role) VALUES ($1, $2)", ["Riley Patel", "requester"]);
    await pool.query("INSERT INTO users (name, role) VALUES ($1, $2)", ["Morgan Diaz", "agent"]);
    await pool.query("INSERT INTO users (name, role) VALUES ($1, $2)", ["Casey Ortiz", "agent"]);
  }

  const firstCompany = (await pool.query("SELECT id FROM companies ORDER BY id LIMIT 1")).rows[0];
  if (firstCompany) {
    await pool.query("UPDATE users SET company_id = $1 WHERE company_id IS NULL", [firstCompany.id]);
    await pool.query("UPDATE tickets SET company_id = $1 WHERE company_id IS NULL", [firstCompany.id]);
  }

  const credentialCount = (await pool.query("SELECT COUNT(*) as count FROM credentials")).rows[0].count;
  if (parseInt(credentialCount) === 0) {
    const users = (await pool.query("SELECT id, name, role FROM users")).rows;
    const passwordHash = "$2b$10$l.WyV73HE3EwPPxltruwxeQdDgLsb0YV4cPKUiArao3Bghh/eaedq";
    for (const user of users) {
      const email = `${user.name.toLowerCase().replace(/\s+/g, ".")}@acme.test`;
      await pool.query(
        "INSERT INTO credentials (user_id, email, password_hash) VALUES ($1, $2, $3)",
        [user.id, email, passwordHash]
      );
    }
  }

  const superAdmin = (await pool.query("SELECT id FROM users WHERE role = 'super_admin'")).rows[0];
  if (!superAdmin) {
    const result = await pool.query(
      "INSERT INTO users (name, role, company_id) VALUES ($1, $2, NULL) RETURNING id",
      ["Platform Admin", "super_admin"]
    );
    const superId = result.rows[0].id;
    await pool.query(
      "INSERT INTO credentials (user_id, email, password_hash) VALUES ($1, $2, $3)",
      [superId, "admin@platform.test", "$2b$10$l.WyV73HE3EwPPxltruwxeQdDgLsb0YV4cPKUiArao3Bghh/eaedq"]
    );
  }

  const planCount = (await pool.query("SELECT COUNT(*) as count FROM plans")).rows[0].count;
  if (parseInt(planCount) === 0) {
    await pool.query("INSERT INTO plans (code, name, price_usd, price_php, icon) VALUES ($1, $2, $3, $4, $5)", ["starter", "Starter", 29, 1499, "🌱"]);
    await pool.query("INSERT INTO plans (code, name, price_usd, price_php, icon) VALUES ($1, $2, $3, $4, $5)", ["growth", "Growth", 99, 4999, "🚀"]);
    await pool.query("INSERT INTO plans (code, name, price_usd, price_php, icon) VALUES ($1, $2, $3, $4, $5)", ["enterprise", "Enterprise", 299, 14999, "🏢"]);
  }

  console.log("Database initialized successfully.");
}

module.exports = { db, pool, initializeDatabase };
