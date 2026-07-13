require("dotenv").config();
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const fs = require("fs");
const path = require("path");

const pool = new Pool({
  connectionString: process.env.SUPABASE_DATABASE_URL || process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});

// Convert SQLite ? placeholders to PostgreSQL $1, $2, ...
function convertPlaceholders(sql) {
  let idx = 0;
  const trimmed = sql.trim();
  const isInsert = /^INSERT\s+INTO/i.test(trimmed);
  const hasReturning = /RETURNING/i.test(trimmed);
  
  const converted = sql.replace(/\?/g, () => `$${++idx}`);
  
  // For INSERT statements, add RETURNING id if not already present
  let finalSql = converted;
  if (isInsert && !hasReturning) {
    finalSql = converted + " RETURNING id";
  }
  
  return finalSql;
}

// Compatibility wrapper that mimics the SQLite `db.prepare().run/get/all` interface
// but uses PostgreSQL via the pg pool
const db = {
  prepare(sql) {
    const convertedSql = convertPlaceholders(sql);
    const stmt = { sql: convertedSql, originalSql: sql };
    return {
      async run(...params) {
        try {
          const result = await pool.query(stmt.sql, params);
          const row = result.rows[0];
          return {
            lastInsertRowid: row ? row.id : null,
            changes: result.rowCount,
          };
        } catch (err) {
          console.error("DB run error:", stmt.originalSql, params, err.message);
          throw err;
        }
      },
      async get(...params) {
        try {
          const result = await pool.query(stmt.sql, params);
          return result.rows[0] || null;
        } catch (err) {
          console.error("DB get error:", stmt.originalSql, params, err.message);
          throw err;
        }
      },
      async all(...params) {
        try {
          const result = await pool.query(stmt.sql, params);
          return result.rows || [];
        } catch (err) {
          console.error("DB all error:", stmt.originalSql, params, err.message);
          throw err;
        }
      },
    };
  },

  async exec(sql) {
    try {
      await pool.query(sql);
    } catch (err) {
      console.error("DB exec error:", sql, err.message);
      throw err;
    }
  },

  async query(sql, params = []) {
    try {
      const convertedSql = convertPlaceholders(sql);
      const result = await pool.query(convertedSql, params);
      return result.rows;
    } catch (err) {
      console.error("DB query error:", sql, params, err.message);
      throw err;
    }
  },

  transaction(fn) {
    return async function (...args) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        // Temporarily replace pool.query with client.query for this transaction
        const originalQuery = pool.query;
        pool.query = (text, params) => client.query(text, params);
        
        const result = await fn(...args);
        
        await client.query("COMMIT");
        pool.query = originalQuery;
        return result;
      } catch (e) {
        await client.query("ROLLBACK");
        pool.query = pool.query;
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

async function initializeDatabase() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS companies (
        id BIGSERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        slug TEXT,
        brand_color TEXT,
        logo_url TEXT,
        invite_required INTEGER NOT NULL DEFAULT 0,
        allowed_domains TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        plan TEXT NOT NULL DEFAULT 'starter',
        trial_ends_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS tickets (
        id BIGSERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        company_id INTEGER NOT NULL DEFAULT 1,
        user_id INTEGER,
        assignee_id INTEGER,
        status TEXT NOT NULL DEFAULT 'open',
        priority TEXT NOT NULL DEFAULT 'medium',
        priority_confidence REAL,
        priority_reason TEXT,
        sla_due_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id BIGSERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        role TEXT NOT NULL,
        company_id INTEGER
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS credentials (
        id BIGSERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS comments (
        id BIGSERIAL PRIMARY KEY,
        ticket_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        body TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS attachments (
        id BIGSERIAL PRIMARY KEY,
        ticket_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        original_name TEXT NOT NULL,
        stored_name TEXT NOT NULL,
        mime_type TEXT NOT NULL,
        size_bytes INTEGER NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id BIGSERIAL PRIMARY KEY,
        actor_id INTEGER,
        company_id INTEGER,
        action TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id INTEGER,
        details TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS payment_requests (
        id BIGSERIAL PRIMARY KEY,
        company_id INTEGER NOT NULL,
        owner_id INTEGER NOT NULL,
        method TEXT NOT NULL,
        reference TEXT,
        amount TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        paid_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS invites (
        id BIGSERIAL PRIMARY KEY,
        company_id INTEGER NOT NULL,
        email TEXT,
        role TEXT NOT NULL DEFAULT 'requester',
        token_hash TEXT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        used_at TIMESTAMPTZ
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS reset_tokens (
        id BIGSERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        token_hash TEXT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        used_at TIMESTAMPTZ
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS plans (
        id BIGSERIAL PRIMARY KEY,
        code TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        price_usd INTEGER NOT NULL,
        price_php INTEGER NOT NULL,
        icon TEXT
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS feedback (
        id BIGSERIAL PRIMARY KEY,
        user_id INTEGER,
        company_id INTEGER,
        message TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    // ── Seed data ────────────────────────────────────────────────
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
      await client.query("INSERT INTO users (name, role) VALUES ($1, $2)", ["Avery Kim", "requester"]);
      await client.query("INSERT INTO users (name, role) VALUES ($1, $2)", ["Jordan Lee", "requester"]);
      await client.query("INSERT INTO users (name, role) VALUES ($1, $2)", ["Riley Patel", "requester"]);
      await client.query("INSERT INTO users (name, role) VALUES ($1, $2)", ["Morgan Diaz", "agent"]);
      await client.query("INSERT INTO users (name, role) VALUES ($1, $2)", ["Casey Ortiz", "agent"]);
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
      await client.query(
        "INSERT INTO plans (code, name, price_usd, price_php, icon) VALUES ($1, $2, $3, $4, $5)",
        ["starter", "Starter", 29, 1499, "🌱"]
      );
      await client.query(
        "INSERT INTO plans (code, name, price_usd, price_php, icon) VALUES ($1, $2, $3, $4, $5)",
        ["growth", "Growth", 99, 4999, "🚀"]
      );
      await client.query(
        "INSERT INTO plans (code, name, price_usd, price_php, icon) VALUES ($1, $2, $3, $4, $5)",
        ["enterprise", "Enterprise", 299, 14999, "🏢"]
      );
    }

    console.log("Database initialized successfully.");
  } catch (err) {
    console.error("Database initialization error:", err);
    throw err;
  } finally {
    client.release();
  }
}

module.exports = { db, pool, initializeDatabase };