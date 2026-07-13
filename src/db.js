if (!process.env.VERCEL) {
  require("dotenv").config();
}
const { Pool } = require("pg");
const { AsyncLocalStorage } = require("async_hooks");

const txStorage = new AsyncLocalStorage();

const DATABASE_URL = process.env.SUPABASE_DATABASE_URL || process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error("FATAL: No database URL configured. Set SUPABASE_DATABASE_URL or DATABASE_URL.");
}

const pool = new Pool({
  connectionString: DATABASE_URL || "postgresql://localhost:5432/notconfigured",
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
  max: 3,
  idleTimeoutMillis: 10000,
  connectionTimeoutMillis: 8000,
  allowExitOnIdle: true,
});

pool.on("error", (err) => {
  console.error("Unexpected pool error:", err.message);
});

function convertPlaceholders(sql) {
  let idx = 0;
  const trimmed = sql.trim();
  const isInsert = /^INSERT\s+INTO/i.test(trimmed);
  const hasReturning = /RETURNING/i.test(trimmed);

  const converted = sql.replace(/\?/g, () => `$${++idx}`);

  let finalSql = converted;
  if (isInsert && !hasReturning) {
    finalSql = converted + " RETURNING id";
  }

  return finalSql;
}

const stmtCache = new Map();

function getCachedSql(sql) {
  let cached = stmtCache.get(sql);
  if (!cached) {
    cached = convertPlaceholders(sql);
    stmtCache.set(sql, cached);
  }
  return cached;
}

function getExecutor() {
  const txClient = txStorage.getStore();
  return txClient || pool;
}

const db = {
  prepare(sql) {
    const convertedSql = getCachedSql(sql);
    return {
      async run(...params) {
        try {
          const result = await getExecutor().query(convertedSql, params);
          const row = result.rows[0];
          return { lastInsertRowid: row ? row.id : null, changes: result.rowCount };
        } catch (err) {
          console.error("DB run error:", err.message);
          throw err;
        }
      },
      async get(...params) {
        try {
          const result = await getExecutor().query(convertedSql, params);
          return result.rows[0] || null;
        } catch (err) {
          console.error("DB get error:", err.message);
          throw err;
        }
      },
      async all(...params) {
        try {
          const result = await getExecutor().query(convertedSql, params);
          return result.rows || [];
        } catch (err) {
          console.error("DB all error:", err.message);
          throw err;
        }
      },
    };
  },

  async exec(sql) {
    try {
      await getExecutor().query(sql);
    } catch (err) {
      console.error("DB exec error:", err.message);
      throw err;
    }
  },

  async query(sql, params = []) {
    try {
      const convertedSql = getCachedSql(sql);
      const result = await getExecutor().query(convertedSql, params);
      return result.rows;
    } catch (err) {
      console.error("DB query error:", err.message);
      throw err;
    }
  },

  transaction(fn) {
    return async function (...args) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const result = await txStorage.run(client, () => fn(...args));
        await client.query("COMMIT");
        return result;
      } catch (e) {
        await client.query("ROLLBACK");
        throw e;
      } finally {
        client.release();
      }
    };
  },

  getPool() {
    return pool;
  },
};

let initDone = false;

async function initializeDatabase() {
  if (initDone) return;
  if (!DATABASE_URL) throw new Error("No database URL configured");

  const client = await pool.connect();
  try {
    const check = await client.query(
      "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'users') as exists"
    );
    if (check.rows[0].exists) {
      initDone = true;
      return;
    }

    await client.query(`
      BEGIN;
      CREATE TABLE IF NOT EXISTS sessions (sid TEXT PRIMARY KEY, sess JSON NOT NULL, expire TIMESTAMPTZ NOT NULL);
      CREATE TABLE IF NOT EXISTS companies (id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, slug TEXT, brand_color TEXT, logo_url TEXT, invite_required INTEGER NOT NULL DEFAULT 0, allowed_domains TEXT, status TEXT NOT NULL DEFAULT 'pending', plan TEXT NOT NULL DEFAULT 'starter', trial_ends_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS tickets (id BIGSERIAL PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL, company_id INTEGER NOT NULL DEFAULT 1, user_id INTEGER, assignee_id INTEGER, status TEXT NOT NULL DEFAULT 'open', priority TEXT NOT NULL DEFAULT 'medium', priority_confidence REAL, priority_reason TEXT, sla_due_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS users (id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL, company_id INTEGER);
      CREATE TABLE IF NOT EXISTS credentials (id BIGSERIAL PRIMARY KEY, user_id INTEGER NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS comments (id BIGSERIAL PRIMARY KEY, ticket_id INTEGER NOT NULL, user_id INTEGER NOT NULL, body TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS attachments (id BIGSERIAL PRIMARY KEY, ticket_id INTEGER NOT NULL, user_id INTEGER NOT NULL, original_name TEXT NOT NULL, stored_name TEXT NOT NULL, mime_type TEXT NOT NULL, size_bytes INTEGER NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS audit_logs (id BIGSERIAL PRIMARY KEY, actor_id INTEGER, company_id INTEGER, action TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id INTEGER, details TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS payment_requests (id BIGSERIAL PRIMARY KEY, company_id INTEGER NOT NULL, owner_id INTEGER NOT NULL, method TEXT NOT NULL, reference TEXT, amount TEXT, status TEXT NOT NULL DEFAULT 'pending', paid_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS invites (id BIGSERIAL PRIMARY KEY, company_id INTEGER NOT NULL, email TEXT, role TEXT NOT NULL DEFAULT 'requester', token_hash TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, used_at TIMESTAMPTZ);
      CREATE TABLE IF NOT EXISTS reset_tokens (id BIGSERIAL PRIMARY KEY, user_id INTEGER NOT NULL, token_hash TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, used_at TIMESTAMPTZ);
      CREATE TABLE IF NOT EXISTS plans (id BIGSERIAL PRIMARY KEY, code TEXT NOT NULL UNIQUE, name TEXT NOT NULL, price_usd INTEGER NOT NULL, price_php INTEGER NOT NULL, icon TEXT);
      CREATE TABLE IF NOT EXISTS feedback (id BIGSERIAL PRIMARY KEY, user_id INTEGER, company_id INTEGER, message TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
      COMMIT;
    `);

    await client.query(`
      BEGIN;
      CREATE INDEX IF NOT EXISTS idx_tickets_company_id ON tickets(company_id);
      CREATE INDEX IF NOT EXISTS idx_tickets_user_id ON tickets(user_id);
      CREATE INDEX IF NOT EXISTS idx_tickets_assignee_id ON tickets(assignee_id);
      CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status);
      CREATE INDEX IF NOT EXISTS idx_tickets_company_status ON tickets(company_id, status);
      CREATE INDEX IF NOT EXISTS idx_tickets_company_created ON tickets(company_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_users_company_id ON users(company_id);
      CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
      CREATE INDEX IF NOT EXISTS idx_credentials_email ON credentials(email);
      CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON credentials(user_id);
      CREATE INDEX IF NOT EXISTS idx_comments_ticket_id ON comments(ticket_id);
      CREATE INDEX IF NOT EXISTS idx_attachments_ticket_id ON attachments(ticket_id);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_company_id ON audit_logs(company_id);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_sessions_expire ON sessions(expire);
      CREATE INDEX IF NOT EXISTS idx_invites_company_id ON invites(company_id);
      CREATE INDEX IF NOT EXISTS idx_reset_tokens_user_id ON reset_tokens(user_id);
      CREATE INDEX IF NOT EXISTS idx_reset_tokens_expires ON reset_tokens(expires_at);
      CREATE INDEX IF NOT EXISTS idx_payment_requests_company_id ON payment_requests(company_id);
      CREATE INDEX IF NOT EXISTS idx_payment_requests_ref_method ON payment_requests(reference, method);
      CREATE INDEX IF NOT EXISTS idx_companies_slug ON companies(slug);
      COMMIT;
    `);

    const bcrypt = require("bcryptjs");

    const companyResult = await client.query("SELECT COUNT(*)::int as count FROM companies");
    if (companyResult.rows[0].count === 0) {
      await client.query(
        "INSERT INTO companies (name, status, plan, created_at) VALUES ($1, $2, $3, NOW())",
        ["Acme", "active", "starter"]
      );
    }

    await client.query(
      "UPDATE companies SET slug = LOWER(REPLACE(name, ' ', '-')) WHERE slug IS NULL"
    );

    const userResult = await client.query("SELECT COUNT(*)::int as count FROM users");
    if (userResult.rows[0].count === 0) {
      for (const [name, role] of [
        ["Avery Kim", "requester"],
        ["Jordan Lee", "requester"],
        ["Riley Patel", "requester"],
        ["Morgan Diaz", "agent"],
        ["Casey Ortiz", "agent"],
      ]) {
        await client.query("INSERT INTO users (name, role) VALUES ($1, $2)", [name, role]);
      }
    }

    const firstCompany = await client.query("SELECT id FROM companies ORDER BY id LIMIT 1");
    if (firstCompany.rows.length > 0) {
      await client.query(
        "UPDATE users SET company_id = $1 WHERE company_id IS NULL AND role != 'super_admin'",
        [firstCompany.rows[0].id]
      );
    }

    const credResult = await client.query("SELECT COUNT(*)::int as count FROM credentials");
    if (credResult.rows[0].count === 0) {
      const users = await client.query("SELECT id, name, role FROM users");
      const passwordHash = "$2b$10$l.WyV73HE3EwPPxltruwxeQdDgLsb0YV4cPKUiArao3Bghh/eaedq";
      for (const user of users.rows) {
        const email = `${user.name.toLowerCase().replace(/\s+/g, ".")}@acme.test`;
        await client.query(
          "INSERT INTO credentials (user_id, email, password_hash) VALUES ($1, $2, $3)",
          [user.id, email, passwordHash]
        );
      }
    }

    const superAdmin = await client.query("SELECT id FROM users WHERE role = 'super_admin' LIMIT 1");
    if (superAdmin.rows.length === 0) {
      await client.query("DELETE FROM credentials WHERE email = 'admin@platform.test'");
      const result = await client.query(
        "INSERT INTO users (name, role, company_id) VALUES ($1, $2, NULL) RETURNING id",
        ["Platform Admin", "super_admin"]
      );
      const superId = result.rows[0].id;
      await client.query(
        "INSERT INTO credentials (user_id, email, password_hash) VALUES ($1, $2, $3)",
        [superId, "admin@platform.test", "$2b$10$l.WyV73HE3EwPPxltruwxeQdDgLsb0YV4cPKUiArao3Bghh/eaedq"]
      );
    }

    const planResult = await client.query("SELECT COUNT(*)::int as count FROM plans");
    if (planResult.rows[0].count === 0) {
      for (const [code, name, usd, php, icon] of [
        ["starter", "Starter", 29, 1499, "🌱"],
        ["growth", "Growth", 99, 4999, "🚀"],
        ["enterprise", "Enterprise", 299, 14999, "🏢"],
      ]) {
        await client.query(
          "INSERT INTO plans (code, name, price_usd, price_php, icon) VALUES ($1, $2, $3, $4, $5)",
          [code, name, usd, php, icon]
        );
      }
    }

    initDone = true;
    console.log("Database initialized successfully.");
  } catch (err) {
    console.error("Database initialization error:", err.message);
    throw err;
  } finally {
    client.release();
  }
}

module.exports = { db, pool, initializeDatabase };
