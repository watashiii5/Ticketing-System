-- Supabase Schema for Ticketing System

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Companies table
CREATE TABLE IF NOT EXISTS companies (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT UNIQUE,
  brand_color TEXT,
  logo_url TEXT,
  invite_required INTEGER NOT NULL DEFAULT 0,
  allowed_domains TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  plan TEXT NOT NULL DEFAULT 'starter',
  trial_ends_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  role TEXT NOT NULL,
  company_id BIGINT REFERENCES companies(id) ON DELETE SET NULL
);

-- Credentials table
CREATE TABLE IF NOT EXISTS credentials (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL
);

-- Tickets table
CREATE TABLE IF NOT EXISTS tickets (
  id BIGSERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  company_id BIGINT NOT NULL DEFAULT 1 REFERENCES companies(id) ON DELETE CASCADE,
  user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
  assignee_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'open',
  priority TEXT NOT NULL DEFAULT 'medium',
  priority_confidence REAL,
  priority_reason TEXT,
  sla_due_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Comments table
CREATE TABLE IF NOT EXISTS comments (
  id BIGSERIAL PRIMARY KEY,
  ticket_id BIGINT NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  body TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Attachments table
CREATE TABLE IF NOT EXISTS attachments (
  id BIGSERIAL PRIMARY KEY,
  ticket_id BIGINT NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  original_name TEXT NOT NULL,
  stored_name TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  size_bytes BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit logs table
CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  actor_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
  company_id BIGINT REFERENCES companies(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id BIGINT,
  details TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Payment requests table
CREATE TABLE IF NOT EXISTS payment_requests (
  id BIGSERIAL PRIMARY KEY,
  company_id BIGINT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  owner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  method TEXT NOT NULL,
  reference TEXT,
  amount TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  paid_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Invites table
CREATE TABLE IF NOT EXISTS invites (
  id BIGSERIAL PRIMARY KEY,
  company_id BIGINT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  email TEXT,
  role TEXT NOT NULL DEFAULT 'requester',
  token_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ
);

-- Reset tokens table
CREATE TABLE IF NOT EXISTS reset_tokens (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ
);

-- Plans table
CREATE TABLE IF NOT EXISTS plans (
  id BIGSERIAL PRIMARY KEY,
  code TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  price_usd INTEGER NOT NULL,
  price_php INTEGER NOT NULL,
  icon TEXT
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_tickets_company_id ON tickets(company_id);
CREATE INDEX IF NOT EXISTS idx_tickets_user_id ON tickets(user_id);
CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status);
CREATE INDEX IF NOT EXISTS idx_tickets_assignee_id ON tickets(assignee_id);
CREATE INDEX IF NOT EXISTS idx_comments_ticket_id ON comments(ticket_id);
CREATE INDEX IF NOT EXISTS idx_attachments_ticket_id ON attachments(ticket_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_company_id ON audit_logs(company_id);
CREATE INDEX IF NOT EXISTS idx_payment_requests_company_id ON payment_requests(company_id);
CREATE INDEX IF NOT EXISTS idx_credentials_email ON credentials(email);
CREATE INDEX IF NOT EXISTS idx_invites_company_id ON invites(company_id);

-- Seed data
INSERT INTO companies (name, status, plan, created_at) 
SELECT 'Acme', 'active', 'starter', NOW()
WHERE NOT EXISTS (SELECT 1 FROM companies LIMIT 1);

INSERT INTO users (name, role) 
SELECT 'Avery Kim', 'requester'
WHERE NOT EXISTS (SELECT 1 FROM users LIMIT 1);

INSERT INTO users (name, role) 
SELECT 'Jordan Lee', 'requester'
WHERE NOT EXISTS (SELECT 1 FROM users WHERE name = 'Jordan Lee');

INSERT INTO users (name, role) 
SELECT 'Riley Patel', 'requester'
WHERE NOT EXISTS (SELECT 1 FROM users WHERE name = 'Riley Patel');

INSERT INTO users (name, role) 
SELECT 'Morgan Diaz', 'agent'
WHERE NOT EXISTS (SELECT 1 FROM users WHERE name = 'Morgan Diaz');

INSERT INTO users (name, role) 
SELECT 'Casey Ortiz', 'agent'
WHERE NOT EXISTS (SELECT 1 FROM users WHERE name = 'Casey Ortiz');

-- Update company slugs
UPDATE companies SET slug = LOWER(REPLACE(name, ' ', '-')) WHERE slug IS NULL;

-- Assign users to first company
UPDATE users SET company_id = (SELECT id FROM companies ORDER BY id LIMIT 1) 
WHERE company_id IS NULL AND role != 'super_admin';

-- Create super admin
INSERT INTO users (name, role, company_id)
SELECT 'Platform Admin', 'super_admin', NULL
WHERE NOT EXISTS (SELECT 1 FROM users WHERE role = 'super_admin');

-- Insert plans
INSERT INTO plans (code, name, price_usd, price_php, icon)
SELECT 'starter', 'Starter', 29, 1499, '🌱'
WHERE NOT EXISTS (SELECT 1 FROM plans WHERE code = 'starter');

INSERT INTO plans (code, name, price_usd, price_php, icon)
SELECT 'growth', 'Growth', 99, 4999, '🚀'
WHERE NOT EXISTS (SELECT 1 FROM plans WHERE code = 'growth');

INSERT INTO plans (code, name, price_usd, price_php, icon)
SELECT 'enterprise', 'Enterprise', 299, 14999, '🏢'
WHERE NOT EXISTS (SELECT 1 FROM plans WHERE code = 'enterprise');