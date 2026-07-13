const express = require("express");
const path = require("path");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const crypto = require("crypto");
const compression = require("compression");
const { db, initializeDatabase } = require("./db");
const { sendTicketNotification } = require("./notifications");
const nodemailer = require("nodemailer");

const app = express();
const port = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

const { Store } = session;
class PgStore extends Store {
  async get(sid, cb) {
    try {
      const res = await db.prepare("SELECT sess FROM sessions WHERE sid = ? AND expire > ?").get(sid, new Date().toISOString());
      cb(null, res ? res.sess : null);
    } catch(e) { cb(e); }
  }
  async set(sid, sess, cb) {
    try {
      const expire = new Date(sess.cookie.expires || Date.now() + 86400000).toISOString();
      await db.prepare(`
        INSERT INTO sessions (sid, sess, expire) VALUES (?, ?, ?)
        ON CONFLICT (sid) DO UPDATE SET sess = EXCLUDED.sess, expire = EXCLUDED.expire
        RETURNING sid
      `).run(sid, JSON.stringify(sess), expire);
      cb(null);
    } catch(e) { cb(e); }
  }
  async destroy(sid, cb) {
    try {
      await db.prepare("DELETE FROM sessions WHERE sid = ?").run(sid);
      cb(null);
    } catch(e) { cb(e); }
  }
}

app.use(
  session({
    store: new PgStore(),
    secret: process.env.SESSION_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 30 * 24 * 60 * 60 * 1000,
    },
  })
);
app.use(
  "/static",
  express.static(path.join(__dirname, "..", "public"), { maxAge: "7d", etag: true })
);
// On Vercel serverless, only /tmp is writable
const isVercel = process.env.VERCEL === "1" || process.env.NODE_ENV === "production";
const uploadsDir = process.env.UPLOADS_DIR
  ? path.resolve(process.env.UPLOADS_DIR)
  : isVercel
    ? "/tmp/uploads"
    : path.join(__dirname, "..", "uploads");
const fs = require("fs");
try {
  if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
  }
} catch (err) {
  console.warn("Could not create uploads directory:", err.message);
}
app.use("/uploads", express.static(uploadsDir));

const upload = multer({
  storage: multer.diskStorage({
    destination: uploadsDir,
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname);
      const name = `${crypto.randomBytes(12).toString("hex")}${ext}`;
      cb(null, name);
    },
  }),
  limits: { fileSize: 8 * 1024 * 1024 },
});

app.use(async (req, res, next) => {
  try {
    if (!req.session.userId) {
      req.user = null;
      return next();
    }

    const user = await db
      .prepare("SELECT id, name, role, company_id FROM users WHERE id = ?")
      .get(req.session.userId);
    req.user = user || null;
    if (req.user && req.user.company_id) {
      req.company = await db
      .prepare("SELECT id, name, slug, brand_color, logo_url, invite_required, allowed_domains, status, plan, trial_ends_at FROM companies WHERE id = ?")
        .get(req.user.company_id);
    } else {
      req.company = null;
    }
    next();
  } catch (err) {
    console.error("Session middleware error:", err.message);
    req.user = null;
    req.company = null;
    next();
  }
});

app.get("/login", async (req, res) => {
  if (req.user) {
    return res.redirect(303, "/");
  }

  res.send(renderLogin());
});

app.get("/forgot", async (req, res) => {
  if (req.user) {
    return res.redirect(303, "/");
  }

  res.send(renderForgot());
});

app.post("/forgot", async (req, res) => {
  const email = (req.body.email || "").trim().toLowerCase();
  if (!email) {
    return res.status(400).send(renderForgot("Email is required."));
  }

  const record = await db
    .prepare(
      `
        SELECT credentials.user_id, users.name
        FROM credentials
        JOIN users ON users.id = credentials.user_id
        WHERE credentials.email = ?
      `
    )
    .get(email);

  if (record) {
    const rawToken = crypto.randomBytes(20).toString("hex");
    const tokenHash = await bcrypt.hash(rawToken, 10);
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();

    await db.prepare(
      "INSERT INTO reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)"
    ).run(record.user_id, tokenHash, expiresAt);

    const resetLink = `${req.protocol}://${req.get("host")}/reset/${rawToken}`;
    sendTicketNotification({
      to: email,
      subject: "Reset your Service Desk password",
      text: `Hi ${record.name},\n\nReset your password using this link (valid for 1 hour):\n${resetLink}`,
    });
  }

  res.send(renderForgot("If the email exists, a reset link was sent."));
});

app.get("/reset/:token", async (req, res) => {
  if (req.user) {
    return res.redirect(303, "/");
  }

  res.send(renderReset(req.params.token));
});

app.post("/reset/:token", async (req, res) => {
  const token = req.params.token;
  const password = req.body.password || "";
  if (!password) {
    return res.status(400).send(renderReset(token, "Password required."));
  }

  // Only load tokens that are unused AND unexpired — avoids wasting bcrypt cycles on dead tokens
  const tokens = await db
    .prepare(
      "SELECT id, user_id, token_hash, expires_at FROM reset_tokens WHERE used_at IS NULL AND expires_at > ? ORDER BY id DESC LIMIT 10"
    )
    .all(new Date().toISOString());

  let matched = null;
  for (const row of tokens) {
    if (await bcrypt.compare(token, row.token_hash)) {
      matched = row;
      break;
    }
  }

  if (!matched) {
    return res.status(400).send(renderReset(token, "Invalid or expired token."));
  }

  const passwordHash = await bcrypt.hash(password, 10);
  await db.prepare("UPDATE credentials SET password_hash = ? WHERE user_id = ?").run(
    passwordHash,
    matched.user_id
  );
  await db.prepare("UPDATE reset_tokens SET used_at = ? WHERE id = ?").run(
    new Date().toISOString(),
    matched.id
  );

  const userCompany = await db
    .prepare("SELECT company_id FROM users WHERE id = ?")
    .get(matched.user_id);
  await logAudit(
    null,
    userCompany ? userCompany.company_id : null,
    "user.reset_password_link",
    "user",
    matched.user_id,
    "password reset"
  );
  res.send(renderLogin("Password reset. You can sign in now."));
});

app.get("/admin/users", requireAuth, requireAgent, requireCompanyActive, async (req, res) => {
  const users = await db
    .prepare(
      `
        SELECT users.id, users.name, users.role, credentials.email
        FROM users
        LEFT JOIN credentials ON credentials.user_id = users.id
        WHERE users.company_id = ?
        ORDER BY users.name
      `
    )
    .all(req.user.company_id);
  const invites = await db
    .prepare(
      "SELECT id, email, role, expires_at, used_at FROM invites WHERE company_id = ? ORDER BY id DESC"
    )
    .all(req.user.company_id);
  res.send(renderUserAdmin(users, invites, req.user));
});

app.post("/admin/users", requireAuth, requireAgent, requireCompanyActive, async (req, res) => {
  const name = (req.body.name || "").trim();
  const email = (req.body.email || "").trim().toLowerCase();
  const role = (req.body.role || "requester").trim();
  const password = req.body.password || "";

  if (!name || !email || !password) {
    return res.status(400).send("Name, email, and password are required.");
  }

  // Enforce agent limit per plan
  if (role === "agent" && req.company) {
    const plan = getEffectivePlan(req.company);
    const limits = getPlanLimits(plan);
    if (limits.maxAgents !== -1) {
      const currentAgents = await getCompanyAgentCount(req.user.company_id);
      if (currentAgents >= limits.maxAgents) {
        return res.status(403).send("Agent limit reached (" + limits.maxAgents + " agents on the " + plan + " plan). Upgrade your plan to add more agents.");
      }
    }
  }


  const passwordHash = await bcrypt.hash(password, 10);
  const insertUser = db.prepare(
    "INSERT INTO users (name, role, company_id) VALUES (?, ?, ?)"
  );
  const insertCred = db.prepare(
    "INSERT INTO credentials (user_id, email, password_hash) VALUES (?, ?, ?)"
  );
  const transaction = db.transaction(async () => {
    const info = await insertUser.run(name, role, req.user.company_id);
    await insertCred.run(info.lastInsertRowid, email, passwordHash);
  });

  await transaction();
  await logAudit(
    req.user.id,
    req.user.company_id,
    "user.create",
    "user",
    null,
    JSON.stringify({ name, email, role })
  );
  res.redirect(303, "/admin/users");
});

app.post("/admin/users/:id/reset", requireAuth, requireAgent, requireCompanyActive, async (req, res) => {
  const id = Number(req.params.id);
  const newPassword = req.body.password || "";
  if (!newPassword) {
    return res.status(400).send("Password required.");
  }

  const passwordHash = await bcrypt.hash(newPassword, 10);
  const user = await db.prepare("SELECT company_id FROM users WHERE id = ?").get(id);
  if (!user || user.company_id !== req.user.company_id) {
    return res.status(403).send("Not allowed.");
  }

  await db.prepare("UPDATE credentials SET password_hash = ? WHERE user_id = ?").run(passwordHash, id);
  await logAudit(req.user.id, req.user.company_id, "user.reset_password", "user", id, "reset password");
  res.redirect(303, "/admin/users");
});

app.get("/admin/plans", requireAuth, requireSuperAdmin, async (req, res) => {
  const plans = await db.prepare("SELECT * FROM plans ORDER BY price_usd ASC").all();
  res.send(renderAdminPlans(plans, req.user));
});

app.post("/admin/plans/:id", requireAuth, requireSuperAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const price_usd = Number(req.body.price_usd);
  const price_php = Number(req.body.price_php);
  
  if (isNaN(price_usd) || isNaN(price_php)) {
    return res.status(400).send("Prices must be valid numbers");
  }

  await db.prepare("UPDATE plans SET price_usd = ?, price_php = ? WHERE id = ?").run(price_usd, price_php, id);
  res.redirect(303, "/admin/plans");
});

app.post("/admin/invites", requireAuth, requireAgent, requireCompanyActive, async (req, res) => {
  const email = (req.body.email || "").trim().toLowerCase();
  const role = (req.body.role || "requester").trim();
  if (!email) {
    return res.status(400).send("Email required.");
  }

  if (req.company && req.company.allowed_domains) {
    const allowed = req.company.allowed_domains
      .split(",")
      .map((item) => item.trim().toLowerCase())
      .filter(Boolean);
    const domain = email.split("@")[1] || "";
    if (allowed.length && !allowed.includes(domain)) {
      return res.status(400).send("Email domain not allowed.");
    }
  }

  const rawToken = crypto.randomBytes(20).toString("hex");
  const tokenHash = await bcrypt.hash(rawToken, 10);
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

  await db.prepare(
    "INSERT INTO invites (company_id, email, role, token_hash, expires_at) VALUES (?, ?, ?, ?, ?)"
  ).run(req.user.company_id, email, role, tokenHash, expiresAt);

  const inviteLink = `${req.protocol}://${req.get("host")}/invite/${rawToken}`;
  sendTicketNotification({
    to: email,
    subject: `You're invited to ${req.company ? req.company.name : "Service Desk"}`,
    text: `Use this invite link to join: ${inviteLink}`,
  });

  await logAudit(req.user.id, req.user.company_id, "invite.create", "company", req.user.company_id, email);
  res.redirect(303, "/admin/users");
});

app.get("/admin/company", requireAuth, requireAgent, requireCompanyActive, async (req, res) => {
  const company = await db
    .prepare(
      "SELECT id, name, slug, brand_color, logo_url, invite_required, allowed_domains, status, plan FROM companies WHERE id = ?"
    )
    .get(req.user.company_id);
  res.send(renderCompanySettings(company, req.user));
});

app.post("/admin/company", requireAuth, requireAgent, requireCompanyActive, async (req, res) => {
  // Gate custom branding to growth+ plans
  if (req.company) {
    const plan = getEffectivePlan(req.company);
    const limits = getPlanLimits(plan);
    if (!limits.customBranding && (req.body.brand_color || req.body.logo_url)) {
      req.body.brand_color = "";
      req.body.logo_url = "";
    }
  }

  const slug = (req.body.slug || "").trim().toLowerCase();
  const brandColor = (req.body.brand_color || "").trim();
  const logoUrl = (req.body.logo_url || "").trim();
  const allowedDomains = (req.body.allowed_domains || "").trim();
  const inviteRequired = req.body.invite_required ? 1 : 0;

  await db.prepare(
    "UPDATE companies SET slug = ?, brand_color = ?, logo_url = ?, invite_required = ?, allowed_domains = ? WHERE id = ?"
  ).run(
    slug || slugify(req.company.name),
    brandColor || null,
    logoUrl || null,
    inviteRequired,
    allowedDomains || null,
    req.user.company_id
  );

  await logAudit(req.user.id, req.user.company_id, "company.update", "company", req.user.company_id, "settings");
  res.redirect(303, "/admin/company");
});

app.post("/login", async (req, res) => {
  const email = (req.body.email || "").trim().toLowerCase();
  const password = req.body.password || "";

  if (!email || !password) {
    return res.status(400).send(renderLogin("Email and password are required."));
  }

  const record = await db
    .prepare(
      `
        SELECT credentials.user_id, credentials.password_hash, users.name, users.role, users.company_id
        FROM credentials
        JOIN users ON users.id = credentials.user_id
        WHERE credentials.email = ?
      `
    )
    .get(email);

  if (!record || !await bcrypt.compare(password, record.password_hash)) {
    return res.status(401).send(renderLogin("Invalid credentials."));
  }

  if (record.company_id) {
    const company = await db
    .prepare("SELECT invite_required, allowed_domains FROM companies WHERE id = ?")
      .get(record.company_id);
    if (company && company.allowed_domains) {
      const allowed = company.allowed_domains
        .split(",")
        .map((item) => item.trim().toLowerCase())
        .filter(Boolean);
      const domain = email.split("@")[1] || "";
      if (allowed.length && !allowed.includes(domain)) {
        return res.status(403).send(renderLogin("Email domain not allowed."));
      }
    }
  }

  req.session.userId = record.user_id;
  res.redirect(303, "/");
});

app.post("/logout", async (req, res) => {
  req.session.destroy(() => {
    res.redirect(303, "/login");
  });
});

app.get("/", async (req, res, next) => {
  if (!req.user) {
    return res.send(renderPublicLanding());
  }
  next();
}, requireCompanyActive, async (req, res) => {
  const isSuper = req.user.role === "super_admin";

  // Super admin gets a completely different management dashboard
  if (isSuper) {
    // Run all independent queries in parallel instead of sequentially
    const [companies, totalTicketsRow, resolvedTicketsRow, totalUsersRow, freeTrialUsersRow, incomeRow, auditLogs, payments] = await Promise.all([
      db.prepare(`
        SELECT c.id, c.name, c.slug, c.status, c.plan, c.trial_ends_at, c.created_at,
          (SELECT COUNT(*) FROM users u WHERE u.company_id = c.id) as user_count,
          (SELECT COUNT(*) FROM tickets t WHERE t.company_id = c.id) as ticket_count
        FROM companies c ORDER BY c.created_at DESC
      `).all(),
      db.prepare("SELECT COUNT(*) as cnt FROM tickets").get(),
      db.prepare("SELECT COUNT(*) as cnt FROM tickets WHERE status = 'resolved'").get(),
      db.prepare("SELECT COUNT(*) as cnt FROM users").get(),
      db.prepare("SELECT COUNT(u.id) as cnt FROM users u JOIN companies c ON c.id = u.company_id WHERE c.status = 'active' AND c.trial_ends_at > ?").get(new Date().toISOString()),
      db.prepare("SELECT SUM(CAST(regexp_replace(amount, '^[$ ]*([0-9]+).*', '\\1') as INTEGER)) as total_income FROM payment_requests WHERE status = 'verified'").get(),
      db.prepare(`
        SELECT al.action, al.details, al.created_at, u.name as actor_name
        FROM audit_logs al
        LEFT JOIN users u ON u.id = al.actor_id
        ORDER BY al.created_at DESC LIMIT 20
      `).all(),
      db.prepare(`
        SELECT pr.id, pr.method, pr.reference, pr.amount, pr.status, pr.created_at, c.name as company_name
        FROM payment_requests pr
        JOIN companies c ON c.id = pr.company_id
        ORDER BY pr.id DESC
        LIMIT 50
      `).all(),
    ]);

    const totalTickets = totalTicketsRow.cnt;
    const resolvedTickets = resolvedTicketsRow.cnt;
    const totalUsers = totalUsersRow.cnt;
    const freeTrialUsers = freeTrialUsersRow.cnt;
    const totalIncomeUsd = incomeRow && incomeRow.total_income ? incomeRow.total_income : 0;
    const activeCompanies = companies.filter(c => c.status === "active").length;
    const trialCompanies = companies.filter(c => c.status === "pending").length;

    return res.send(renderSuperAdminDashboard({
      companies,
      totalTickets,
      resolvedTickets,
      totalUsers,
      freeTrialUsers,
      totalIncomeUsd,
      activeCompanies,
      trialCompanies,
      auditLogs,
      payments
    }, req.user));
  }

  const isAgent = req.user.role === "agent";
  
  let query = `
    SELECT
      tickets.id,
      tickets.title,
      tickets.description,
      tickets.status,
      tickets.priority,
      tickets.priority_confidence,
      tickets.priority_reason,
      tickets.sla_due_at,
      tickets.created_at,
      tickets.assignee_id,
      requester.name as requester_name,
      requester.role as requester_role,
      assignee.name as assignee_name
    FROM tickets
    LEFT JOIN users requester ON requester.id = tickets.user_id
    LEFT JOIN users assignee ON assignee.id = tickets.assignee_id
  `;
  let queryParams = [];

  if (isAgent) {
    query += " WHERE tickets.company_id = ? ORDER BY tickets.id DESC LIMIT 50";
    queryParams.push(req.user.company_id);
  } else {
    query += " WHERE tickets.company_id = ? AND tickets.user_id = ? ORDER BY tickets.id DESC LIMIT 50";
    queryParams.push(req.user.company_id, req.user.id);
  }

  const tickets = await db.prepare(query).all(...queryParams);

  const users = await db.prepare("SELECT id, name, role FROM users WHERE company_id = ? ORDER BY name").all(req.user.company_id);
  const ticketIds = tickets.map((ticket) => ticket.id);
  const commentsByTicketId = ticketIds.length
    ? await getCommentsByTicketId(ticketIds)
    : {};
  const attachmentsByTicketId = ticketIds.length
    ? await getAttachmentsByTicketId(ticketIds)
    : {};

  // Pre-compute ticket usage for plan limits
  let ticketUsageHtml = '';
  if (req.company) {
    const plan = getEffectivePlan(req.company);
    const limits = getPlanLimits(plan);
    if (limits.maxTicketsPerMonth !== -1) {
      const used = await getCompanyTicketsThisMonth(req.company.id);
      const pct = Math.round((used / limits.maxTicketsPerMonth) * 100);
      const color = pct >= 90 ? '#ef4444' : pct >= 70 ? '#f59e0b' : 'var(--accent)';
      ticketUsageHtml = '<div><span class="stat" style="color:' + color + ';">' + used + '/' + limits.maxTicketsPerMonth + '</span><span class="label">Tickets this month</span></div>';
    }
  }

  res.send(await renderHome(
      tickets,
      users,
      commentsByTicketId,
      attachmentsByTicketId,
      { tab: req.query.tab || 'active' },
      req.user,
      req.company,
      ticketUsageHtml
    )
  );
});


app.get("/api/queue", requireAuth, requireCompanyActive, async (req, res) => {
  const isAgent = req.user.role === "agent";
  
  let query = `
    SELECT
      tickets.id,
      tickets.title,
      tickets.description,
      tickets.status,
      tickets.priority,
      tickets.priority_confidence,
      tickets.priority_reason,
      tickets.sla_due_at,
      tickets.created_at,
      tickets.assignee_id,
      requester.name as requester_name,
      requester.role as requester_role,
      assignee.name as assignee_name
    FROM tickets
    LEFT JOIN users requester ON requester.id = tickets.user_id
    LEFT JOIN users assignee ON assignee.id = tickets.assignee_id
  `;
  let queryParams = [];

  if (isAgent) {
    query += " WHERE tickets.company_id = ? ORDER BY tickets.id DESC LIMIT 50";
    queryParams.push(req.user.company_id);
  } else {
    query += " WHERE tickets.company_id = ? AND tickets.user_id = ? ORDER BY tickets.id DESC LIMIT 50";
    queryParams.push(req.user.company_id, req.user.id);
  }

  const tickets = await db.prepare(query).all(...queryParams);

  const ticketIds = tickets.map((ticket) => ticket.id);
  const commentsByTicketId = ticketIds.length
    ? await getCommentsByTicketId(ticketIds)
    : {};
  const attachmentsByTicketId = ticketIds.length
    ? await getAttachmentsByTicketId(ticketIds)
    : {};

  const html = renderTicketListHtml(tickets, commentsByTicketId, attachmentsByTicketId, req.user, req.query.tab || 'active');
  res.send(html);
});

app.post("/tickets", requireAuth, requireCompanyActive, async (req, res) => {
  const title = (req.body.title || "").trim();
  const description = (req.body.description || "").trim();
  const requesterId = req.user.id;
  const rawSla = (req.body.sla_due_at || "").trim();

  const priorityResult =
    req.user.role === "agent"
      ? { level: (req.body.priority || "medium").trim(), confidence: 1, reason: "agent set" }
      : inferPriority(`${title} ${description}`);
  const priority = priorityResult.level;

  if (!title || !description) {
    return res.status(400).send("Title and description are required.");
  }

  // Enforce ticket limit per plan
  if (req.company) {
    const plan = getEffectivePlan(req.company);
    const limits = getPlanLimits(plan);
    if (limits.maxTicketsPerMonth !== -1) {
      const ticketsThisMonth = await getCompanyTicketsThisMonth(req.user.company_id);
      if (ticketsThisMonth >= limits.maxTicketsPerMonth) {
        return res.status(403).send("Monthly ticket limit reached (" + limits.maxTicketsPerMonth + " tickets on the " + plan + " plan). Upgrade your plan for more tickets.");
      }
    }
  }


  const now = new Date().toISOString();
  const slaDueAt = rawSla
    ? new Date(rawSla).toISOString()
    : computeSlaDueAt(priority);
  const companyIdForTicket = req.user.role === "super_admin" ? 1 : req.user.company_id;
  
  const result = await db
    .prepare(
      "INSERT INTO tickets (title, description, company_id, user_id, status, priority, priority_confidence, priority_reason, sla_due_at, created_at) VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?, ?)"
    )
    .run(
      title,
      description,
      companyIdForTicket,
      requesterId,
      priority,
      priorityResult.confidence,
      priorityResult.reason,
      slaDueAt,
      now
    );

  await notifyTicketCreated(result.lastInsertRowid, title, description, priority, req.user);
  await logAudit(
    req.user.id,
    req.user.company_id,
    "ticket.create",
    "ticket",
    result.lastInsertRowid,
    title
  );

  res.redirect(303, "/");
});

app.post("/tickets/:id/comment", requireAuth, requireCompanyActive, async (req, res) => {
  const id = Number(req.params.id);
  const body = (req.body.body || "").trim();

  if (!body) {
    return res.status(400).send("Comment is required.");
  }

  const now = new Date().toISOString();
  await db.prepare(
    "INSERT INTO comments (ticket_id, user_id, body, created_at) VALUES (?, ?, ?, ?)"
  ).run(id, req.user.id, body, now);

  await notifyTicketCommented(id, body, req.user);
  await logAudit(
    req.user.id,
    req.user.company_id,
    "ticket.comment",
    "ticket",
    id,
    body.slice(0, 120)
  );
  res.redirect(303, "/");
});

app.post(
  "/tickets/:id/attachments",
  requireAuth,
  requireCompanyActive,
  upload.single("attachment"),
  async (req, res) => {
    const id = Number(req.params.id);
    if (!req.file) {
      return res.status(400).send("Attachment required.");
    }

    const now = new Date().toISOString();
    await db.prepare(
      `
        INSERT INTO attachments
        (ticket_id, user_id, original_name, stored_name, mime_type, size_bytes, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `
    ).run(
      id,
      req.user.id,
      req.file.originalname,
      req.file.filename,
      req.file.mimetype,
      req.file.size,
      now
    );

    await logAudit(
      req.user.id,
      req.user.company_id,
      "ticket.attachment",
      "ticket",
      id,
      req.file.originalname
    );
    res.redirect(303, "/");
  }
);

app.post("/tickets/:id/attachments/:attachmentId/delete", requireAuth, requireCompanyActive, async (req, res) => {
  const ticketId = Number(req.params.id);
  const attachmentId = Number(req.params.attachmentId);
  
  // Ensure the ticket belongs to the user's company
  const ticket = await db.prepare("SELECT id FROM tickets WHERE id = ? AND company_id = ?").get(ticketId, req.user.company_id);
  if (!ticket) return res.status(404).send("Ticket not found.");

  const attachment = await db.prepare("SELECT id, stored_name FROM attachments WHERE id = ? AND ticket_id = ?").get(attachmentId, ticketId);
  if (!attachment) return res.status(404).send("Attachment not found.");

  await db.prepare("DELETE FROM attachments WHERE id = ?").run(attachmentId);

  // Try to delete the file from disk
  const fs = require("fs");
  const filePath = path.join(uploadsDir, attachment.stored_name);
  try { fs.unlinkSync(filePath); } catch {}

  await logAudit(req.user.id, req.user.company_id, "ticket.attachment.delete", "attachment", attachmentId, attachment.stored_name);
  res.redirect(303, "/");
});

app.get("/search", requireAuth, requireCompanyActive, async (req, res) => {
  const status = (req.query.status || "all").trim();
  const priority = (req.query.priority || "all").trim();
  const term = (req.query.q || "").trim();

  const params = [];
  const filters = [];

  if (status !== "all") {
    filters.push("tickets.status = ?");
    params.push(status);
  }

  if (priority !== "all") {
    filters.push("tickets.priority = ?");
    params.push(priority);
  }

  if (term) {
    filters.push("(tickets.title LIKE ? OR tickets.description LIKE ?)");
    params.push(`%${term}%`, `%${term}%`);
  }

  if (req.user.role !== "agent" && req.user.role !== "super_admin") {
    filters.push("tickets.user_id = ?");
    params.push(req.user.id);
  }

  if (req.user.role !== "super_admin") {
    filters.push("tickets.company_id = ?");
    params.push(req.user.company_id);
  }

  const whereClause = filters.length ? `WHERE ${filters.join(" AND ")}` : "";

  const tickets = await db
    .prepare(
      `
        SELECT
          tickets.id,
          tickets.title,
          tickets.description,
          tickets.status,
          tickets.priority,
          tickets.sla_due_at,
          tickets.created_at,
          requester.name as requester_name,
          requester.role as requester_role,
          assignee.name as assignee_name
        FROM tickets
        LEFT JOIN users requester ON requester.id = tickets.user_id
        LEFT JOIN users assignee ON assignee.id = tickets.assignee_id
        ${whereClause}
        ORDER BY tickets.id DESC
      `
    )
    .all(...params);

  const users = await db.prepare("SELECT id, name, role FROM users ORDER BY name").all();
  const ticketIds = tickets.map((ticket) => ticket.id);
  const commentsByTicketId = ticketIds.length
    ? await getCommentsByTicketId(ticketIds)
    : {};
  const attachmentsByTicketId = ticketIds.length
    ? await getAttachmentsByTicketId(ticketIds)
    : {};

  res.send(await renderHome(
      tickets,
      users,
      commentsByTicketId,
      attachmentsByTicketId,
      { status, priority, term },
      req.user,
      req.company,
      ""
    )
  );
});

app.get("/audit-logs", requireAuth, requireAgent, requireCompanyActive, async (req, res) => {
  // Audit logs: enterprise only
  if (req.company) {
    const plan = getEffectivePlan(req.company);
    const limits = getPlanLimits(plan);
    if (!limits.auditLogs) {
      return res.status(403).send("Audit logs are available on the Enterprise plan. Please upgrade.");
    }
  }
  const logs = await db.prepare("SELECT audit_logs.*, users.name as actor_name FROM audit_logs LEFT JOIN users ON users.id = audit_logs.actor_id WHERE audit_logs.company_id = ? ORDER BY audit_logs.id DESC LIMIT 100").all(req.user.company_id);
  res.send(renderAuditLogs(logs, req.user));
});


app.get("/reports", requireAuth, requireAgent, requireCompanyActive, async (req, res) => {
  const isSuper = req.user.role === "super_admin";
  const compFilter = isSuper ? "" : "WHERE company_id = ?";
  const compFilterAnd = isSuper ? "" : "AND company_id = ?";
  const params = isSuper ? [] : [req.user.company_id];

  const total = Number((await db
    .prepare(`SELECT COUNT(*) as count FROM tickets ${compFilter}`)
    .get(...params))?.count ?? 0);
  const open = Number((await db
    .prepare(`SELECT COUNT(*) as count FROM tickets WHERE status = 'open' ${compFilterAnd}`)
    .get(...params))?.count ?? 0);
  const inProgress = Number((await db
    .prepare(
      `SELECT COUNT(*) as count FROM tickets WHERE status = 'in_progress' ${compFilterAnd}`
    )
    .get(...params))?.count ?? 0);
  const resolved = Number((await db
    .prepare(`SELECT COUNT(*) as count FROM tickets WHERE status = 'resolved' ${compFilterAnd}`)
    .get(...params))?.count ?? 0);
  const overdue = Number((await db
    .prepare(
      `SELECT COUNT(*) as count FROM tickets WHERE sla_due_at IS NOT NULL AND sla_due_at < ? AND status != 'resolved' ${compFilterAnd}`
    )
    .get(new Date().toISOString(), ...params))?.count ?? 0);

  const topPriorities = await db
    .prepare(
      `SELECT priority, COUNT(*) as count FROM tickets ${compFilter} GROUP BY priority ORDER BY count DESC`
    )
    .all(...params);


  // Advanced analytics data for growth+ plans
  let advancedData = null;
  const plan = req.company ? getEffectivePlan(req.company) : 'enterprise';
  const limits = getPlanLimits(plan);
  
  if (limits.advancedAnalytics) {
    const avgResolutionTime = await db.prepare(`
      SELECT AVG(
        (CASE WHEN status = 'resolved' THEN EXTRACT(EPOCH FROM created_at) ELSE EXTRACT(EPOCH FROM NOW()) END - EXTRACT(EPOCH FROM created_at))
      ) / 3600.0 as avg_hours
      FROM tickets ${compFilter}
    `).get(...params);
    
    const ticketsByDay = await db.prepare(`
      SELECT created_at::date as day, COUNT(*) as count
      FROM tickets ${compFilter}
      GROUP BY created_at::date
      ORDER BY day DESC
      LIMIT 14
    `).all(...params);

    const agentPerformance = await db.prepare(`
      SELECT users.name, COUNT(tickets.id) as assigned_count,
        SUM(CASE WHEN tickets.status = 'resolved' THEN 1 ELSE 0 END) as resolved_count
      FROM users
      LEFT JOIN tickets ON tickets.assignee_id = users.id
      WHERE users.company_id = ? AND users.role = 'agent'
      GROUP BY users.id
    `).all(req.user.company_id);

    advancedData = {
      avgResolutionHours: avgResolutionTime ? Math.round((avgResolutionTime.avg_hours || 0) * 10) / 10 : 0,
      ticketsByDay,
      agentPerformance
    };
  }

  res.send(
    renderReports(
      { total, open, inProgress, resolved, overdue, topPriorities, advancedData, currentPlan: plan },
      req.user
    )
  );
});

app.post("/tickets/:id/status", requireAuth, requireAgent, requireCompanyActive, async (req, res) => {
  const id = Number(req.params.id);
  const status = (req.body.status || "open").trim();
  const allowed = new Set(["open", "in_progress", "resolved"]);

  if (!allowed.has(status)) {
    return res.status(400).send("Invalid status.");
  }

  const result = await db.prepare("UPDATE tickets SET status = ? WHERE id = ? AND company_id = ?").run(status, id, req.user.company_id);
  if (result.changes === 0) {
    return res.status(404).send("Ticket not found.");
  }
  await notifyTicketStatus(id, status, req.user);
  await logAudit(req.user.id, req.user.company_id, "ticket.status", "ticket", id, status);
  res.redirect(303, "/");
});

app.post("/tickets/:id/priority", requireAuth, requireAgent, requireCompanyActive, async (req, res) => {
  const id = Number(req.params.id);
  const priority = (req.body.priority || "medium").trim();
  const allowed = new Set(["low", "medium", "high"]);
  const reason = (req.body.reason || "").trim();

  if (!allowed.has(priority)) {
    return res.status(400).send("Invalid priority.");
  }

  const slaDueAt = computeSlaDueAt(priority);
  await db.prepare(
    "UPDATE tickets SET priority = ?, priority_confidence = ?, priority_reason = ?, sla_due_at = ? WHERE id = ? AND company_id = ?"
  ).run(priority, 1, reason || "agent override", slaDueAt, id, req.user.company_id);
  await notifyTicketPriority(id, priority, req.user);
  await logAudit(
    req.user.id,
    req.user.company_id,
    "ticket.priority",
    "ticket",
    id,
    reason ? `${priority} | ${reason}` : priority
  );
  res.redirect(303, "/");
});

app.post("/tickets/:id/assign", requireAuth, requireAgent, requireCompanyActive, async (req, res) => {
  const id = Number(req.params.id);
  const assigneeId = Number(req.body.assignee_id || 0) || null;

  await db.prepare("UPDATE tickets SET assignee_id = ? WHERE id = ? AND company_id = ?").run(assigneeId, id, req.user.company_id);
  await notifyTicketAssigned(id, assigneeId, req.user);
  await logAudit(
    req.user.id,
    req.user.company_id,
    "ticket.assign",
    "ticket",
    id,
    String(assigneeId || "none")
  );
  res.redirect(303, "/");
});

app.post("/tickets/:id/sla", requireAuth, requireAgent, requireCompanyActive, async (req, res) => {
  // Custom SLA rules: enterprise only
  if (req.company) {
    const plan = getEffectivePlan(req.company);
    const limits = getPlanLimits(plan);
    if (!limits.customSla) {
      return res.status(403).send("Custom SLA rules are available on the Enterprise plan. Please upgrade.");
    }
  }

  const id = Number(req.params.id);
  const raw = (req.body.sla_due_at || "").trim();
  if (!raw) {
    return res.status(400).send("SLA due date required.");
  }

  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) {
    return res.status(400).send("Invalid SLA date.");
  }

  await db.prepare("UPDATE tickets SET sla_due_at = ? WHERE id = ? AND company_id = ?").run(
    parsed.toISOString(),
    id,
    req.user.company_id
  );
  await notifyTicketSla(id, parsed.toISOString(), req.user);
  await logAudit(
    req.user.id,
    req.user.company_id,
    "ticket.sla",
    "ticket",
    id,
    parsed.toISOString()
  );
  res.redirect(303, "/");
});

app.post("/tickets/:id/delete", requireAuth, requireAgent, requireCompanyActive, async (req, res) => {
  const id = Number(req.params.id);
  await db.prepare("DELETE FROM tickets WHERE id = ? AND company_id = ?").run(id, req.user.company_id);
  await logAudit(req.user.id, req.user.company_id, "ticket.delete", "ticket", id, "deleted");
  res.redirect(303, "/");
});


app.get("/admin/companies/:id", requireAuth, requireSuperAdmin, async (req, res) => {
  const company = await db.prepare("SELECT * FROM companies WHERE id = ?").get(req.params.id);
  if (!company) return res.status(404).send("Company not found");
  const plans = await db.prepare("SELECT * FROM plans").all();
  res.send(renderCompanyAdmin(company, plans, req.user));
});

app.post("/admin/companies/:id/action", requireAuth, requireSuperAdmin, async (req, res) => {
  const id = req.params.id;
  const action = req.body.action;
  
  if (action === "delete") {
    const transaction = db.transaction(async () => {
      await db.prepare("DELETE FROM tickets WHERE company_id = ?").run(id);
      await db.prepare("DELETE FROM audit_logs WHERE company_id = ?").run(id);
      
      const users = await db.prepare("SELECT id FROM users WHERE company_id = ?").all(id);
      if (users && users.length > 0) {
        for (const u of users) {
          await db.prepare("DELETE FROM credentials WHERE user_id = ?").run(u.id);
        }
      }
      
      await db.prepare("DELETE FROM users WHERE company_id = ?").run(id);
      await db.prepare("DELETE FROM payment_requests WHERE company_id = ?").run(id);
      await db.prepare("DELETE FROM companies WHERE id = ?").run(id);
    });
    await transaction();
    await logAudit(req.user.id, 1, "admin.company_deleted", "company", id, "Company and all associated data deleted");
    return res.redirect(303, "/");
  }

  if (action === "update") {
    const plan = req.body.plan;
    const status = req.body.status;
    let trialEndsAt = req.body.trial_ends_at || null;
    
    if (trialEndsAt) {
      trialEndsAt = new Date(trialEndsAt).toISOString();
    }
    
    await db.prepare("UPDATE companies SET plan = ?, status = ?, trial_ends_at = ? WHERE id = ?").run(plan, status, trialEndsAt, id);
    await logAudit(req.user.id, 1, "admin.company_updated", "company", id, `Updated ${plan}, ${status}`);
    return res.redirect(303, "/");
  }
  
  res.redirect(303, "/");
});

app.get("/platform", requireAuth, requireSuperAdmin, async (req, res) => {
  const companies = await db
    .prepare(
      `
        SELECT
          companies.id,
          companies.name,
          companies.status,
          companies.plan,
          companies.created_at,
          COUNT(users.id) as users
        FROM companies
        LEFT JOIN users ON users.company_id = companies.id
        GROUP BY companies.id
        ORDER BY companies.created_at DESC
      `
    )
    .all();
  const payments = await db
    .prepare(
      `
        SELECT payment_requests.id, payment_requests.method, payment_requests.reference,
               payment_requests.amount, payment_requests.status, payment_requests.created_at,
               companies.name as company_name
        FROM payment_requests
        JOIN companies ON companies.id = payment_requests.company_id
        ORDER BY payment_requests.id DESC
      `
    )
    .all();
  res.send(renderPlatformAdmin(companies, payments, req.user));
});

app.post("/platform/companies/:id/approve", requireAuth, requireSuperAdmin, async (req, res) => {
  const id = Number(req.params.id);
  await db.prepare("UPDATE companies SET status = 'active' WHERE id = ?").run(id);
  await logAudit(req.user.id, null, "company.approve", "company", id, "approved");
  res.redirect(303, "/platform");
});

app.post("/platform/companies/:id/suspend", requireAuth, requireSuperAdmin, async (req, res) => {
  const id = Number(req.params.id);
  await db.prepare("UPDATE companies SET status = 'suspended' WHERE id = ?").run(id);
  await logAudit(req.user.id, null, "company.suspend", "company", id, "suspended");
  res.redirect(303, "/platform");
});

app.post("/billing/verify", requireAuth, requireSuperAdmin, async (req, res) => {
  const id = Number(req.body.request_id || 0);
  const request = await db
    .prepare("SELECT company_id FROM payment_requests WHERE id = ?")
    .get(id);

  if (!request) {
    return res.status(404).send("Payment request not found.");
  }

  await db.prepare("UPDATE payment_requests SET status = 'paid', paid_at = ? WHERE id = ?").run(
    new Date().toISOString(),
    id
  );
  await db.prepare("UPDATE companies SET status = 'active' WHERE id = ?").run(request.company_id);
  await logAudit(req.user.id, null, "billing.verified", "company", request.company_id, "paid");
  res.redirect(303, "/platform");
});

app.get("/signup", async (req, res) => {
  if (req.user) {
    return res.redirect(303, "/");
  }
  res.send(renderSignup());
});

app.get("/c/:slug", async (req, res) => {
  const slug = (req.params.slug || "").trim().toLowerCase();
  const company = await db
    .prepare(
      "SELECT id, name, slug, brand_color, logo_url, invite_required, allowed_domains, status FROM companies WHERE slug = ?"
    )
    .get(slug);
  if (!company) {
    return res.status(404).send("Company not found.");
  }

  res.send(renderCompanyLanding(company));
});

app.post("/c/:slug/join", async (req, res) => {
  const slug = (req.params.slug || "").trim().toLowerCase();
  const name = (req.body.name || "").trim();
  const email = (req.body.email || "").trim().toLowerCase();
  const password = req.body.password || "";

  if (!name || !email || !password) {
    return res.status(400).send("Name, email, and password are required.");
  }

  const company = await db.prepare("SELECT id, name, invite_required, allowed_domains FROM companies WHERE slug = ?").get(slug);
  if (!company) return res.status(404).send("Company not found.");
  
  if (company.invite_required) {
    return res.status(403).send("This company requires an invite to join.");
  }

  if (company.allowed_domains) {
    const allowed = company.allowed_domains.split(",").map(i => i.trim().toLowerCase()).filter(Boolean);
    const domain = email.split("@")[1] || "";
    if (allowed.length && !allowed.includes(domain)) {
      return res.status(403).send("Your email domain is not allowed to auto-join this company.");
    }
  }

  const existing = await db.prepare("SELECT user_id FROM credentials WHERE email = ?").get(email);
  if (existing) return res.status(400).send("Email already in use.");

  const passwordHash = await bcrypt.hash(password, 10);
  const createUser = db.prepare("INSERT INTO users (name, role, company_id) VALUES (?, 'requester', ?)");
  const createCred = db.prepare("INSERT INTO credentials (user_id, email, password_hash) VALUES (?, ?, ?)");
  
  const transaction = db.transaction(async () => {
    const userId = (await createUser.run(name, company.id)).lastInsertRowid;
    await createCred.run(userId, email, passwordHash);
    return userId;
  });

  const userId = await transaction();
  req.session.userId = userId;
  res.redirect(303, "/");
});

app.post("/demo", async (req, res) => {
  const role = req.body.role === "requester" ? "requester" : "agent";
  const randomStr = crypto.randomBytes(8).toString("hex") + Date.now().toString(36);
  const companyName = `Demo Inc ${randomStr.slice(0, 8)}`;
  const slug = `demo-${randomStr}`;
  const now = new Date().toISOString();
  const trialEndsAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  const passwordHash = await bcrypt.hash("password123", 10);

  const createCompany = db.prepare(
    "INSERT INTO companies (name, slug, invite_required, allowed_domains, status, plan, trial_ends_at, created_at) VALUES (?, ?, 0, ?, 'active', 'starter', ?, ?)"
  );
  const createUser = db.prepare(
    "INSERT INTO users (name, role, company_id) VALUES (?, ?, ?)"
  );
  const createCred = db.prepare(
    "INSERT INTO credentials (user_id, email, password_hash) VALUES (?, ?, ?)"
  );

  const transaction = db.transaction(async () => {
    const companyId = (await createCompany.run(companyName, slug, `${slug}.test`, trialEndsAt, now)).lastInsertRowid;

    // Always create both users so the demo company is fully functional
    const agentId = (await createUser.run("IT Support Agent", "agent", companyId)).lastInsertRowid;
    await createCred.run(agentId, `agent@${slug}.test`, passwordHash);

    const requesterId = (await createUser.run("Employee User", "requester", companyId)).lastInsertRowid;
    await createCred.run(requesterId, `user@${slug}.test`, passwordHash);

    // Seed sample tickets from the requester
    const ticketInsert = db.prepare("INSERT INTO tickets (title, description, company_id, user_id, status, priority, priority_confidence, priority_reason, created_at, sla_due_at) VALUES (?, ?, ?, ?, 'open', ?, 1, 'demo', ?, ?)");
    await ticketInsert.run("Cannot access payroll", "I am getting a 403 error when accessing the payroll system. This is urgent.", companyId, requesterId, "high", now, computeSlaDueAt("high"));
    await ticketInsert.run("Need a new monitor", "My current monitor is flickering and gives me headaches.", companyId, requesterId, "low", now, computeSlaDueAt("low"));
    await ticketInsert.run("VPN not connecting", "I can't connect to the company VPN from home. Tried restarting.", companyId, requesterId, "medium", now, computeSlaDueAt("medium"));

    return role === "agent" ? agentId : requesterId;
  });

  req.session.userId = await transaction();
  res.redirect(303, "/");
});


app.post("/signup", async (req, res) => {
  const companyName = (req.body.company_name || "").trim();
  const name = (req.body.name || "").trim();
  const email = (req.body.email || "").trim().toLowerCase();
  const password = req.body.password || "";
  const plan = (req.body.plan || "starter").trim();
  const slug = (req.body.slug || "").trim().toLowerCase();
  const domains = (req.body.allowed_domains || "").trim();
  const inviteRequired = req.body.invite_required ? 1 : 0;

  if (!companyName || !name || !email || !password) {
    return res.status(400).send(renderSignup("All fields are required."));
  }

  let finalDomains = domains;
  if (domains) {
    const allowed = domains
      .split(",")
      .map((item) => item.trim().toLowerCase())
      .filter(Boolean);
    const domain = email.split("@")[1] || "";
    if (domain && !allowed.includes(domain)) {
      allowed.push(domain);
      finalDomains = allowed.join(", ");
    }
  }

  const now = new Date().toISOString();
  const trialEndsAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  const passwordHash = await bcrypt.hash(password, 10);
  const createCompany = db.prepare(
    "INSERT INTO companies (name, slug, invite_required, allowed_domains, status, plan, trial_ends_at, created_at) VALUES (?, ?, ?, ?, 'active', 'starter', ?, ?)"
  );
  const createUser = db.prepare(
    "INSERT INTO users (name, role, company_id) VALUES (?, 'agent', ?)"
  );
  const createCred = db.prepare(
    "INSERT INTO credentials (user_id, email, password_hash) VALUES (?, ?, ?)"
  );

  const transaction = db.transaction(async () => {
    const companyId = (await createCompany.run(
      companyName,
      slug || slugify(companyName),
      inviteRequired,
      finalDomains,
      trialEndsAt,
      now
    )).lastInsertRowid;
    const userId = (await createUser.run(name, companyId)).lastInsertRowid;
    await createCred.run(userId, email, passwordHash);
    await logAudit(userId, companyId, "company.signup", "company", companyId, plan);
    return userId;
  });

  try {
    req.session.userId = await transaction();
    res.redirect(303, "/");
  } catch (err) {
    console.error("Signup error:", err);
    return res.status(400).send(renderSignup("This email or company name is already registered, or an error occurred. Please try a different email."));
  }
});

app.get("/billing", requireAuth, async (req, res) => {
  if (req.user.role === "super_admin") {
    return res.redirect(303, "/platform");
  }

  const company = await db
    .prepare("SELECT id, name, status, plan, trial_ends_at FROM companies WHERE id = ?")
    .get(req.user.company_id);
  const payments = await db
    .prepare(
      "SELECT id, method, reference, amount, status, created_at FROM payment_requests WHERE company_id = ? ORDER BY id DESC"
    )
    .all(req.user.company_id);
  const plans = await db.prepare("SELECT * FROM plans ORDER BY price_usd ASC").all();

  res.send(renderBilling(company, payments, plans, req.user));
});


app.post("/billing/request", requireAuth, async (req, res) => {
  const planCode = (req.body.plan || "").trim();
  const method = (req.body.method || "manual").trim();
  const reference = (req.body.reference || "").trim();
  const company = await db
    .prepare("SELECT id, status FROM companies WHERE id = ?")
    .get(req.user.company_id);

  if (!company) {
    return res.status(400).send("Company not found.");
  }

  // Get price from the selected plan
  const plan = await db.prepare("SELECT price_usd, price_php FROM plans WHERE code = ?").get(planCode);
  const amount = plan ? `$${plan.price_usd} USD / ₱${plan.price_php} PHP` : 'custom';

  // Update company plan
  if (planCode) {
    await db.prepare("UPDATE companies SET plan = ? WHERE id = ?").run(planCode, company.id);
  }

  await db.prepare(
    "INSERT INTO payment_requests (company_id, owner_id, method, reference, amount, status, created_at) VALUES (?, ?, ?, ?, ?, 'pending', ?)"
  ).run(company.id, req.user.id, method, reference, amount, new Date().toISOString());

  await logAudit(req.user.id, req.user.company_id, "billing.request", "company", company.id, `${planCode} via ${method}`);
  res.redirect(303, "/billing");
});

app.post("/billing/trial", requireAuth, async (req, res) => {
  const planCode = (req.body.plan || "starter").trim();
  const company = await db.prepare("SELECT id, trial_ends_at FROM companies WHERE id = ?").get(req.user.company_id);

  if (!company) {
    return res.status(400).send("Company not found.");
  }
  
  if (company.trial_ends_at) {
    return res.status(400).send("A trial has already been started for this company.");
  }

  const trialEndsAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  await db.prepare("UPDATE companies SET plan = ?, trial_ends_at = ?, status = 'active' WHERE id = ?").run(planCode, trialEndsAt, company.id);

  await logAudit(req.user.id, req.user.company_id, "billing.trial_started", "company", company.id, `Trial for ${planCode}`);
  res.redirect(303, "/");
});

app.post("/webhooks/stripe", async (req, res) => {
  const { reference, status } = req.body;
  if (!reference) return res.status(400).send("Missing reference");
  
  if (status === "succeeded") {
    const request = await db.prepare("SELECT id, company_id FROM payment_requests WHERE reference = ? AND method = 'stripe'").get(reference);
    if (request) {
      await db.prepare("UPDATE payment_requests SET status = 'paid', paid_at = ? WHERE id = ?").run(new Date().toISOString(), request.id);
      await db.prepare("UPDATE companies SET status = 'active' WHERE id = ?").run(request.company_id);
    }
  }
  res.send({ received: true });
});

app.post("/webhooks/paypal", async (req, res) => {
  const { reference, status } = req.body;
  if (status === "COMPLETED" && reference) {
    const request = await db.prepare("SELECT id, company_id FROM payment_requests WHERE reference = ? AND method = 'paypal'").get(reference);
    if (request) {
      await db.prepare("UPDATE payment_requests SET status = 'paid', paid_at = ? WHERE id = ?").run(new Date().toISOString(), request.id);
      await db.prepare("UPDATE companies SET status = 'active' WHERE id = ?").run(request.company_id);
    }
  }
  res.send({ received: true });
});

app.post("/webhooks/gcash", async (req, res) => {
  const { reference, status } = req.body;
  if (status === "paid" && reference) {
    const request = await db.prepare("SELECT id, company_id FROM payment_requests WHERE reference = ? AND method = 'gcash'").get(reference);
    if (request) {
      await db.prepare("UPDATE payment_requests SET status = 'paid', paid_at = ? WHERE id = ?").run(new Date().toISOString(), request.id);
      await db.prepare("UPDATE companies SET status = 'active' WHERE id = ?").run(request.company_id);
    }
  }
  res.send({ received: true });
});

app.get("/invite/:token", async (req, res) => {
  if (req.user) {
    return res.redirect(303, "/");
  }

  res.send(renderInviteAccept(req.params.token));
});

app.post("/invite/:token", async (req, res) => {
  const token = req.params.token;
  const name = (req.body.name || "").trim();
  const password = req.body.password || "";
  if (!name || !password) {
    return res.status(400).send(renderInviteAccept(token, "Name and password required."));
  }

  // Only load invites that are unused AND unexpired — avoids wasting bcrypt cycles on dead invites
  const invites = await db
    .prepare(
      "SELECT id, company_id, email, role, token_hash, expires_at FROM invites WHERE used_at IS NULL AND expires_at > ? ORDER BY id DESC LIMIT 10"
    )
    .all(new Date().toISOString());

  let matched = null;
  for (const row of invites) {
    if (await bcrypt.compare(token, row.token_hash)) {
      matched = row;
      break;
    }
  }

  if (!matched) {
    return res.status(400).send(renderInviteAccept(token, "Invalid or expired invite."));
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const createUser = db.prepare(
    "INSERT INTO users (name, role, company_id) VALUES (?, ?, ?)"
  );
  const createCred = db.prepare(
    "INSERT INTO credentials (user_id, email, password_hash) VALUES (?, ?, ?)"
  );

  const transaction = db.transaction(async () => {
    const userId = (await createUser.run(name, matched.role, matched.company_id)).lastInsertRowid;
    await createCred.run(userId, matched.email, passwordHash);
    await db.prepare("UPDATE invites SET used_at = ? WHERE id = ?").run(
      new Date().toISOString(),
      matched.id
    );
  });

  await transaction();
  res.send(renderLogin("Invite accepted. You can sign in now."));
});

const feedbackTransport = process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD
  ? nodemailer.createTransport({
      service: "gmail",
      auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD },
    })
  : null;

app.post("/feedback", requireAuth, async (req, res) => {
  const message = (req.body.message || "").trim();
  if (!message) {
    return res.redirect(303, "/");
  }

  await db.prepare("INSERT INTO feedback (user_id, company_id, message, created_at) VALUES (?, ?, ?, ?)").run(
    req.user.id,
    req.user.company_id,
    message,
    new Date().toISOString()
  );

  if (feedbackTransport) {
    try {
      const credRow = await db.prepare("SELECT email FROM credentials WHERE user_id = ?").get(req.user.id);
      const userEmail = credRow ? credRow.email : null;

      await feedbackTransport.sendMail({
        from: `"Service Desk Feedback" <${process.env.GMAIL_USER}>`,
        to: "qtimescheduler@gmail.com",
        replyTo: userEmail || undefined,
        subject: `[Feedback] ${req.user.name} (${req.company?.name || "unknown"})`,
        text: `From: ${req.user.name} (${req.user.role})\nCompany: ${req.company?.name || "N/A"}\nEmail: ${userEmail || "N/A"}\n\n${message}`,
        html: `<p><strong>From:</strong> ${escapeHtml(req.user.name)} (${req.user.role})<br><strong>Company:</strong> ${escapeHtml(req.company?.name || "N/A")}<br><strong>Email:</strong> ${escapeHtml(userEmail || "N/A")}</p><p>${escapeHtml(message).replace(/\n/g, "<br>")}</p>`,
      });
    } catch (err) {
      console.error("Feedback email error:", err.message);
    }
  }

  res.redirect(303, "/");
});

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err.message);
  if (res.headersSent) return next(err);
  res.status(500).send("<h1>Something went wrong</h1><p>Please try again.</p>");
});

// Only auto-start when run directly (not when imported by Vercel API handler)
if (require.main === module) {
  initializeDatabase().then(() => {
    app.listen(port, () => {
      console.log(`Ticketing app running on http://localhost:${port}`);
    });
  }).catch(err => {
    console.error("Failed to initialize database:", err);
    process.exit(1);
  });
}

// Export for Vercel serverless and testing
module.exports = { app, initializeDatabase };


function renderTicketListHtml(tickets, commentsByTicketId, attachmentsByTicketId, currentUser, currentTab = 'active') {
  const displayedTickets = tickets.filter(t => currentTab === 'active' ? t.status !== 'resolved' : t.status === 'resolved');

  if (displayedTickets.length === 0) {
    return `<ul id="ticket-queue-list" class="ticket-list" style="list-style: none; padding: 0;"><li style="text-align: center; padding: 40px; color: var(--muted);">No tickets found.</li></ul>`;
  }

  const rows = displayedTickets.map(ticket => `
        <li class="ticket bg-${escapeHtml(ticket.priority)}">
          <div class="ticket-header">
            <div>
              <h3>${escapeHtml(ticket.title)}</h3>
              <p>${escapeHtml(ticket.description)}</p>
              <p class="requester">Requested by ${escapeHtml(
                ticket.requester_name || "Unassigned"
              )}</p>
              <p class="assignee">Assignee: ${escapeHtml(
                ticket.assignee_name || "Unassigned"
              )}</p>
            </div>
            <div class="meta">
              <span class="badge status ${escapeHtml(ticket.status)}">${escapeHtml(formatStatus(ticket.status))}</span>
              <span class="badge priority ${escapeHtml(ticket.priority)}">${escapeHtml(ticket.priority)}</span>
              ${renderPriorityMeta(ticket.priority_confidence, ticket.priority_reason)}
              ${renderSlaBadge(ticket.sla_due_at)}
              <span class="timestamp">${new Date(ticket.created_at).toLocaleString()}</span>
            </div>
          </div>
          <div class="ticket-actions">
            ${
              currentUser.role === "agent" || currentUser.role === "super_admin"
                ? `
                  <div style="display: flex; gap: 10px; align-items: center; width: 100%;">
                    <form action="/tickets/${ticket.id}/status" method="post">
                      ${ticket.status === 'open' ? `<input type="hidden" name="status" value="in_progress"><button type="submit" class="primary-btn glow-btn" style="padding: 8px 16px;">▶ Start Processing</button>` : ''}
                      ${ticket.status === 'in_progress' ? `<input type="hidden" name="status" value="resolved"><button type="submit" style="padding: 8px 16px; background: #10b981; color: white; border: none; border-radius: 6px; cursor: pointer;">✔ Resolve Issue</button>` : ''}
                      ${ticket.status === 'resolved' ? `<input type="hidden" name="status" value="open"><button type="submit" class="ghost" style="padding: 8px 16px;">↺ Reopen</button>` : ''}
                    </form>

                    <form action="/tickets/${ticket.id}/assign" method="post">
                      ${ticket.assignee_id === currentUser.id 
                        ? `<input type="hidden" name="assignee_id" value=""><button type="submit" class="ghost" style="padding: 8px 16px;">Release Job</button>` 
                        : `<input type="hidden" name="assignee_id" value="${currentUser.id}"><button type="submit" class="ghost" style="padding: 8px 16px;">✋ Claim Job</button>`
                      }
                    </form>

                    <form action="/tickets/${ticket.id}/priority" method="post" style="display: flex; gap: 5px; margin-left: auto;">
                      <select name="priority" style="padding: 6px 10px; font-size: 13px; border-radius: 4px; border: 1px solid var(--border); background: var(--panel);">
                        ${renderOption("low", ticket.priority)}
                        ${renderOption("medium", ticket.priority)}
                        ${renderOption("high", ticket.priority)}
                      </select>
                      <button type="submit" class="ghost" style="padding: 6px 12px; font-size: 13px;">Set Priority</button>
                    </form>
                  </div>
                `
                : ""
            }
          </div>
          <div class="comment-block">
            <h4>Comments</h4>
            <ul class="comments">
              ${renderComments(commentsByTicketId[ticket.id])}
            </ul>
            <form action="/tickets/${ticket.id}/comment" method="post" class="comment-form">
              <input name="body" placeholder="Add update or resolution note" required />
              <button type="submit">Add comment</button>
            </form>
          </div>
          <div class="attachment-block">
            <h4>Attachments</h4>
            <ul class="attachments">
              ${renderAttachments(attachmentsByTicketId[ticket.id], ticket.id)}
            </ul>
            <form action="/tickets/${ticket.id}/attachments" method="post" enctype="multipart/form-data" class="attachment-form">
              <input type="file" name="attachment" accept="image/*" capture="environment" required />
              <button type="submit">Upload</button>
            </form>
          </div>
        </li>
      `
  ).join("");
  return `${queueHtml}`;
}

async function renderHome(
  tickets,
  users,
  commentsByTicketId,
  attachmentsByTicketId,
  filters = null,
  currentUser,
  currentCompany,
  ticketUsageHtml = ""
) {
  const agentOptions = users
    .filter((user) => user.role === "agent")
    .map((user) => `<option value="${user.id}">${escapeHtml(user.name)}</option>`)
    .join("");

  const filterStatus = filters?.status || "all";
  const filterPriority = filters?.priority || "all";
  const filterTerm = filters?.term || "";
  const trialBanner = renderTrialBanner(currentCompany);

  const filterParams = { status: filterStatus, q: filterTerm };
  if (currentUser.role === "agent") {
    filterParams.priority = filterPriority;
  }
  const filterQuery = new URLSearchParams(filterParams).toString();
  
  const currentTab = filters?.tab || 'active';
  const displayedTickets = tickets.filter(t => currentTab === 'active' ? t.status !== 'resolved' : t.status === 'resolved');
  const queueHtml = renderTicketListHtml(tickets, commentsByTicketId, attachmentsByTicketId, currentUser, currentTab);

  return `
    <!doctype html>
    <html lang="en">
      <head>
        <script>if(localStorage.getItem('theme')==='dark') document.documentElement.classList.add('dark-mode');</script>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>IT Ticketing Desk</title>
        <link rel="stylesheet" href="/static/styles.css" />
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/intro.js/7.2.0/introjs.min.css" />
      </head>
      <body>
        <main class="shell" data-title="Welcome!" data-intro="Welcome to your IT Service Desk. Let's take a quick tour." style="--brand:${
          currentCompany?.brand_color ? escapeHtml(currentCompany.brand_color) : "#d26a2b"
        }">
          <header class="topbar">
            <div>
              <h2 style="display:flex;align-items:center;gap:12px;"><img src="${currentCompany?.logo_url ? escapeHtml(currentCompany.logo_url) : '/static/logo.png'}" alt="Logo" style="height:32px;border-radius:8px;"> ${escapeHtml(currentCompany?.name || "Service Desk")}</h2>
              <p>Signed in as ${escapeHtml(currentUser.name)} (${escapeHtml(currentUser.role)})</p>
            </div>
            <div class="top-actions" data-title="Navigation" data-intro="Access reports, users, and settings from here.">
              ${
                currentUser.role === "agent"
                  ? `
                    <a class="ghost" href="/reports">Reports</a>
                    <a class="ghost" href="/admin/users">Users</a>
                    <a class="ghost" href="/admin/company">Company</a>
                    ${(function(){ if(currentCompany) { const p = getEffectivePlan(currentCompany); const l = getPlanLimits(p); if(l.auditLogs) return '<a class="ghost" href="/audit-logs">Audit Logs</a>'; } return ''; })()}
                  `
                  : ""
              }
              <button type="button" class="primary-btn glow-btn" onclick="introJs().setOption('showProgress', true).start()">Tutorial</button>
              <button type="button" class="ghost" onclick="document.getElementById('feedback-modal').style.display='flex'">Feedback</button>
              <form action="/logout" method="post">
                <button type="submit" class="ghost">Log out</button>
              </form>
            </div>
          </header>
          ${trialBanner}
          <section class="hero" data-title="Dashboard Stats" data-intro="Track your ticket volume and open issues at a glance.">
            <div>
              <p class="eyebrow">Internal IT Support</p>
              <h1>Ticketing Desk</h1>
              <p class="subtitle">Track requests, priorities, and progress in one shared queue.</p>
            </div>
            <div class="stats">
              <div>
                <span class="stat">${tickets.length}</span>
                <span class="label">Total tickets</span>
              </div>
              ${ticketUsageHtml}
              <div>
                <span class="stat">${tickets.filter((t) => t.status === "open").length}</span>
                <span class="label">Open</span>
              </div>
              <div>
                <span class="stat">${tickets.filter((t) => t.status === "in_progress").length}</span>
                <span class="label">In progress</span>
              </div>
            </div>
          </section>

          <section class="panel">
            <form class="ticket-form" action="/tickets" method="post" data-title="Create Tickets" data-intro="Need help? Fill out this form to submit a new request.">
              <div>
                <label for="title">Title</label>
                <input id="title" name="title" placeholder="Laptop won't boot" required />
              </div>
              ${
                currentUser.role === "agent"
                  ? `
                    <div>
                      <label for="priority">Priority</label>
                      <select id="priority" name="priority">
                        <option value="low">Low</option>
                        <option value="medium" selected>Medium</option>
                        <option value="high">High</option>
                      </select>
                    </div>
                  `
                  : ""
              }
              <div>
                <label>Requester</label>
                <div class="readonly">${escapeHtml(currentUser.name)}</div>
              </div>
              <div class="full">
                <label for="description">Description</label>
                <textarea id="description" name="description" rows="3" placeholder="Describe the issue and any urgency..." required></textarea>
              </div>
              <div class="full actions">
                <button type="submit">Create ticket</button>
              </div>
            </form>
          </section>

          <section class="panel" data-title="Your Queue" data-intro="View and manage your active and resolved tickets here. Use the tabs and filters to find what you need.">
            <h2 style="display:flex;align-items:center;gap:12px;"><img src="/static/logo.png" alt="Logo" style="height:32px;border-radius:8px;"> Queue</h2>
            <div class="tabs" style="margin-bottom: 20px;">
              <a href="/?tab=active" class="tab-link ${currentTab === 'active' ? 'is-active' : ''}">Active Tickets</a>
              <a href="/?tab=resolved" class="tab-link ${currentTab === 'resolved' ? 'is-active' : ''}">Resolved Tickets</a>
            </div>
            
            <form class="filters ${currentUser.role === "agent" ? "" : "single"}" action="/search" method="get" style="margin-bottom: 20px; padding-bottom: 20px; border-bottom: 1px solid var(--border);">
              <div>
                <label for="filter-status">Status</label>
                <select id="filter-status" name="status">
                  ${renderOption("all", filterStatus, "All")}
                  ${renderOption("open", filterStatus)}
                  ${renderOption("in_progress", filterStatus, "In progress")}
                  ${renderOption("resolved", filterStatus)}
                </select>
              </div>
              ${
                currentUser.role === "agent"
                  ? `
                    <div>
                      <label for="filter-priority">Priority</label>
                      <select id="filter-priority" name="priority">
                        ${renderOption("all", filterPriority, "All")}
                        ${renderOption("low", filterPriority)}
                        ${renderOption("medium", filterPriority)}
                        ${renderOption("high", filterPriority)}
                      </select>
                    </div>
                  `
                  : ""
              }
              <div>
                <label for="filter-term">Search</label>
                <input id="filter-term" name="q" value="${escapeHtml(filterTerm)}" placeholder="Search tickets" />
              </div>
              <div class="filter-actions">
                <button type="submit">Apply filters</button>
              </div>
            </form>

            <p class="filter-note"><span>Showing ${displayedTickets.length} ticket(s)</span><span><a href="/search?${filterQuery}">Permalink</a> • <a href="/">Clear filters</a></span></p>
            <ul class="tickets">
              ${rows || "<li class=\"empty\">No tickets yet. Add the first request above.</li>"}
            </ul>
          </section>
        </main>
        <script>
          const SCROLL_KEY = 'desk_scroll';
          const saved = sessionStorage.getItem(SCROLL_KEY);
          if (saved) { window.scrollTo(0, parseInt(saved)); sessionStorage.removeItem(SCROLL_KEY); }

          document.querySelectorAll('form[action^="/tickets/"]').forEach(form => {
            if (form.enctype === 'multipart/form-data') return;
            form.addEventListener('submit', async (e) => {
              e.preventDefault();
              sessionStorage.setItem(SCROLL_KEY, window.scrollY);
              const data = new URLSearchParams(new FormData(form));
              try {
                const r = await fetch(form.action, { method:'POST', body:data, redirect:'follow' });
                if (r.redirected || r.ok) location.reload();
                else alert('Action failed.');
              } catch { location.reload(); }
            });
          });

          document.querySelectorAll('.attachment-form').forEach(form => {
            const inp = form.querySelector('input[type="file"]');
            const btn = form.querySelector('button[type="submit"]');
            btn.style.display = 'none';
            let pv = null;
            inp.addEventListener('change', () => {
              if (pv) { pv.remove(); pv = null; }
              const f = inp.files[0]; if (!f) return;
              btn.style.display = '';
              pv = document.createElement('div');
              pv.style.cssText = 'margin-top:8px;padding:10px;border:1px solid var(--border);border-radius:8px;background:var(--panel)';
              if (f.type.startsWith('image/')) {
                const img = document.createElement('img');
                img.style.cssText = 'max-width:200px;max-height:150px;border-radius:6px;display:block;margin-bottom:6px';
                img.src = URL.createObjectURL(f);
                pv.appendChild(img);
              }
              const sp = document.createElement('span');
              sp.style.cssText = 'font-size:12px;color:var(--muted)';
              sp.textContent = f.name + ' (' + (f.size/1024).toFixed(1) + ' KB)';
              pv.appendChild(sp);
              form.insertBefore(pv, btn);
            });
            form.addEventListener('submit', e => {
              if (!confirm('Upload "' + inp.files[0]?.name + '"?')) e.preventDefault();
              else sessionStorage.setItem(SCROLL_KEY, window.scrollY);
            });
          });

          document.querySelectorAll('.tabs a').forEach(el => {
            el.addEventListener('click', () => sessionStorage.setItem(SCROLL_KEY, window.scrollY));
          });
        </script>

        <div id="feedback-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:1000;align-items:center;justify-content:center;" onclick="if(event.target===this)this.style.display='none'">
          <div style="background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:28px;width:90%;max-width:440px;box-shadow:0 20px 60px rgba(0,0,0,0.3);">
            <h3 style="margin:0 0 4px 0;">Send Feedback</h3>
            <p style="color:var(--muted);font-size:13px;margin:0 0 16px 0;">Your feedback goes directly to the developer.</p>
            <form action="/feedback" method="post" style="display:flex;flex-direction:column;gap:12px;">
              <textarea name="message" required rows="4" placeholder="Bug report, feature request, or general feedback..." style="width:100%;padding:10px 12px;border:1px solid var(--border);border-radius:8px;background:var(--surface);color:var(--ink);font-family:inherit;resize:vertical;box-sizing:border-box;"></textarea>
              <div style="display:flex;gap:10px;justify-content:flex-end;">
                <button type="button" class="ghost" onclick="document.getElementById('feedback-modal').style.display='none'" style="padding:8px 18px;">Cancel</button>
                <button type="submit" class="primary-btn" style="padding:8px 18px;">Send</button>
              </div>
            </form>
          </div>
        </div>
      
    <script>
      (function() {
        const isDark = document.documentElement.classList.contains('dark-mode');
        
        window.addEventListener('DOMContentLoaded', () => {
          const btn = document.createElement('div');
          btn.className = 'floating-theme-toggle';
          btn.innerHTML = isDark ? '☀️' : '🌙';
          document.body.appendChild(btn);
          
          btn.addEventListener('click', () => {
            const isDarkNow = document.documentElement.classList.toggle('dark-mode');
            localStorage.setItem('theme', isDarkNow ? 'dark' : 'light');
            btn.innerHTML = isDarkNow ? '☀️' : '🌙';
          });
        });
      })();
    </script>
    
    <script src="https://cdnjs.cloudflare.com/ajax/libs/morphdom/2.7.0/morphdom-umd.min.js"></script>
    <script>
      let isPollingPaused = false;

      document.addEventListener('focusin', (e) => {
        if (e.target.closest('#ticket-queue-list') && (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT')) {
          isPollingPaused = true;
        }
      });

      document.addEventListener('focusout', (e) => {
        if (e.target.closest('#ticket-queue-list')) {
          isPollingPaused = false;
        }
      });

      async function pollQueue() {
        if (isPollingPaused) {
          setTimeout(pollQueue, 10000);
          return;
        }
        try {
          const tab = new URLSearchParams(window.location.search).get('tab') || 'active';
          const res = await fetch('/api/queue?tab=' + tab);
          if (res.ok) {
            const html = await res.text();
            const currentQueue = document.getElementById('ticket-queue-list');
            if (currentQueue) {
              morphdom(currentQueue, html, {
                onBeforeElUpdated: function(fromEl, toEl) {
                  if (fromEl === document.activeElement && (fromEl.tagName === 'INPUT' || fromEl.tagName === 'TEXTAREA' || fromEl.tagName === 'SELECT')) {
                    return false;
                  }
                  return true;
                }
              });
            }
          }
        } catch (err) {
          console.error('Polling error:', err);
        }
        setTimeout(pollQueue, 10000);
      }
      setTimeout(pollQueue, 10000);
    </script>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/intro.js/7.2.0/intro.min.js"></script>
  
    <script>
      document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', (e) => {
          const btn = form.querySelector('button[type="submit"]');
          if (btn) {
            setTimeout(() => {
              btn.disabled = true;
              btn.innerHTML = '<span class="spinner"></span> Processing...';
            }, 10);
          }
        });
      });
    </script>

      </body>
    </html>
  `;
}

async function getCommentsByTicketId(ticketIds) {
  const placeholders = ticketIds.map((_, i) => `$${i + 1}`).join(",");
  const rows = await db
    .prepare(
      `
        SELECT comments.id, comments.ticket_id, comments.body, comments.created_at, users.name as author
        FROM comments
        JOIN users ON users.id = comments.user_id
        WHERE comments.ticket_id IN (${placeholders})
        ORDER BY comments.created_at ASC
      `
    )
    .all(...ticketIds);

  return rows.reduce((acc, row) => {
    if (!acc[row.ticket_id]) acc[row.ticket_id] = [];
    acc[row.ticket_id].push(row);
    return acc;
  }, {});
}

async function getAttachmentsByTicketId(ticketIds) {
  const placeholders = ticketIds.map((_, i) => `$${i + 1}`).join(",");
  const rows = await db
    .prepare(
      `
        SELECT id, ticket_id, original_name, stored_name, size_bytes
        FROM attachments
        WHERE ticket_id IN (${placeholders})
        ORDER BY created_at ASC
      `
    )
    .all(...ticketIds);

  return rows.reduce((acc, row) => {
    if (!acc[row.ticket_id]) acc[row.ticket_id] = [];
    acc[row.ticket_id].push(row);
    return acc;
  }, {});
}

function requireAuth(req, res, next) {
  if (!req.user) {
    return res.redirect(303, "/login");
  }
  next();
}

function requireAgent(req, res, next) {
  if (!req.user || (req.user.role !== "agent" && req.user.role !== "super_admin")) {
    return res.status(403).send("Agent access required.");
  }
  next();
}

function requireSuperAdmin(req, res, next) {
  if (!req.user || req.user.role !== "super_admin") {
    return res.status(403).send("Platform admin only.");
  }
  next();
}

async function requireCompanyActive(req, res, next) {
  if (req.user && req.user.role === "super_admin") return next();

  // Reuse req.company already loaded by the session middleware — avoids a redundant DB query per request
  const company = req.company;
  if (!company) {
    return res.status(402).send(renderBillingGate(req.user));
  }

  if (company.plan === "pending_plan") {
    return res.redirect(303, "/billing");
  }

  if (company.status === "active") {
    if (!company.trial_ends_at) return next();
    const trialEndsAt = new Date(company.trial_ends_at);
    if (Date.now() <= trialEndsAt.getTime()) return next();
    return res.status(402).send(renderBillingGate(req.user));
  }

  return res.status(402).send(renderBillingGate(req.user));
}

function slugify(value) {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, "")
    .trim()
    .replace(/\s+/g, "-");
}

function getPlanLimits(planCode) {
  const limits = {
    free_trial: { maxAgents: 3, maxTicketsPerMonth: 50, emailNotifications: false, advancedAnalytics: false, customBranding: false, apiAccess: false, customSla: false, auditLogs: false },
    starter:    { maxAgents: 5, maxTicketsPerMonth: 100, emailNotifications: true, advancedAnalytics: false, customBranding: false, apiAccess: false, customSla: false, auditLogs: false },
    growth:     { maxAgents: 20, maxTicketsPerMonth: -1, emailNotifications: true, advancedAnalytics: true, customBranding: true, apiAccess: false, customSla: false, auditLogs: false },
    enterprise: { maxAgents: -1, maxTicketsPerMonth: -1, emailNotifications: true, advancedAnalytics: true, customBranding: true, apiAccess: true, customSla: true, auditLogs: true },
  };
  return limits[planCode] || limits.starter;
}

async function getCompanyAgentCount(companyId) {
  return (await db.prepare("SELECT COUNT(*) as count FROM users WHERE company_id = ? AND role = 'agent'").get(companyId)).count;
}

async function getCompanyTicketsThisMonth(companyId) {
  const now = new Date();
  const firstDay = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();
  return (await db.prepare("SELECT COUNT(*) as count FROM tickets WHERE company_id = ? AND created_at >= ?").get(companyId, firstDay)).count;
}

function getEffectivePlan(company) {
  if (!company) return 'starter';
  if (company.trial_ends_at && company.status !== 'active') return 'free_trial';
  return company.plan || 'starter';
}

async function logAudit(actorId, companyId, action, entityType, entityId, details) {
  await db.prepare(
    "INSERT INTO audit_logs (actor_id, company_id, action, entity_type, entity_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
  ).run(
    actorId,
    companyId,
    action,
    entityType,
    entityId,
    details,
    new Date().toISOString()
  );
}

function computeSlaDueAt(priority) {
  const days = priority === "high" ? 1 : priority === "medium" ? 3 : 5;
  return new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
}

function inferPriority(text) {
  const content = text.toLowerCase();
  const highSignals = [
    "down",
    "outage",
    "cannot",
    "can't",
    "urgent",
    "security",
    "breach",
    "locked out",
    "ransom",
    "phishing",
    "data loss",
    "vpn",
    "email down",
    "server",
    "payroll",
    "critical",
    "blocked",
    "system offline",
    "no access",
    "account locked",
    "compromised",
    "malware",
    "virus",
    "fraud",
    "p1",
    "sev1",
    "high impact",
    "production",
    "finance",
    "hr payroll",
    "emergency",
    "unusable",
    "downtime",
    "data leak",
    "hacked",
    "kahit ano",
    "napuputol",
    "hindi gumagana",
    "sira",
    "urgent",
    "agarang",
    "kritikal",
    "critical",
    "naka-lock",
    "na-lock",
    "hindi maka-login",
    "di makalogin",
    "hindi makapag-login",
    "walang access",
    "walang internet",
    "patay ang server",
    "hindi ma-access",
    "nawala ang data",
    "na-hack",
    "may virus",
    "may malware",
    "phishing",
    "hindi maka-connect",
    "walang koneksyon",
    "network down",
    "system down",
    "email down",
    "vpn down",
  ];
  const mediumSignals = [
    "slow",
    "error",
    "failed",
    "issue",
    "problem",
    "printer",
    "wifi",
    "network",
    "access",
    "bug",
    "glitch",
    "timeout",
    "lag",
    "intermittent",
    "unstable",
    "degraded",
    "p2",
    "sev2",
    "performance",
    "sync",
    "latency",
    "cannot print",
    "print",
    "scanner",
    "software install",
    "update",
    "license",
    "password reset",
    "needs access",
    "permission",
    "mabagal",
    "error",
    "may problema",
    "issue",
    "nagla-lag",
    "nagha-hang",
    "hindi stable",
    "pasulpot-sulpot",
    "paminsan",
    "mahina",
    "hindi makapag-print",
    "printer",
    "scanner",
    "wifi",
    "network",
    "access",
    "kailangan ng access",
    "kailangan ng permiso",
    "kulang sa permiso",
    "hindi ma-update",
    "update",
    "install",
    "software",
    "setup",
    "may error",
    "hindi gumagana ng maayos",
  ];

  const highHit = highSignals.find((signal) => content.includes(signal));
  if (highHit) {
    return { level: "high", confidence: 0.9, reason: `keyword: ${highHit}` };
  }

  const mediumHit = mediumSignals.find((signal) => content.includes(signal));
  if (mediumHit) {
    return { level: "medium", confidence: 0.7, reason: `keyword: ${mediumHit}` };
  }

  return { level: "low", confidence: 0.4, reason: "default" };
}

function renderSlaBadge(slaDueAt) {
  if (!slaDueAt) return "";
  const due = new Date(slaDueAt);
  const overdue = Date.now() > due.getTime();
  const label = overdue ? "Overdue" : "Due";
  return `<span class="badge sla ${overdue ? "overdue" : "ontrack"}">${label} ${due.toLocaleDateString()}</span>`;
}

function renderPriorityMeta(confidence, reason) {
  if (confidence === null || confidence === undefined) return "";
  const percent = Math.round(Number(confidence) * 100);
  const label = Number.isNaN(percent) ? "AI" : `AI ${percent}%`;
  const detail = reason ? ` • ${escapeHtml(reason)}` : "";
  return `<span class="meta-pill">${label}${detail}</span>`;
}

function renderTrialBanner(currentCompany) {
  if (!currentCompany) return "";
  if (!currentCompany.trial_ends_at) return "";

  const endsAt = new Date(currentCompany.trial_ends_at);
  const msLeft = endsAt.getTime() - Date.now();
  const daysLeft = Math.ceil(msLeft / (1000 * 60 * 60 * 24));
  
  if (daysLeft > 0) {
    return `
      <div class="trial-banner">
        <strong>⏳ Free trial:</strong> ${daysLeft} day${daysLeft === 1 ? '' : 's'} remaining.
        <span style="margin-left: auto; display: flex; gap: 10px; align-items: center;">
          <span style="font-size: 13px; opacity: 0.8;">Expires ${endsAt.toLocaleDateString()}</span>
          <a href="/billing" style="background: white; color: var(--accent); padding: 4px 14px; border-radius: 4px; text-decoration: none; font-weight: 600;">View Plans</a>
        </span>
      </div>
    `;
  }

  return "";
}

function renderLogin(error = "") {
  return `
    <!doctype html>
    <html lang="en">
      <head>
        <script>if(localStorage.getItem('theme')==='dark') document.documentElement.classList.add('dark-mode');</script>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Login • Service Desk</title>
        <link rel="stylesheet" href="/static/styles.css" />
      </head>
      <body>
        <main class="shell login-shell">
          <section class="panel login-panel">
            <div style="text-align: center; margin-bottom: 24px;">
              <img src="/static/logo.png" alt="Logo" style="height: 64px; border-radius: 12px; margin-bottom: 16px;">
              <h1 style="margin: 0;">Sign in</h1>
            </div>
            <p class="subtitle">Access your company's service desk.</p>
            ${error ? `<p class=\"error\">${escapeHtml(error)}</p>` : ""}
            <form class="login-form" action="/login" method="post">
              <label for="email">Email</label>
              <input id="email" name="email" type="email" required />
              <label for="password">Password</label>
              <div class="password-field">
                <input id="password" name="password" type="password" required />
                <button type="button" class="icon-button" data-toggle="password">👁</button>
              </div>
              <button type="submit">Log in</button>
            </form>
            <p class="helper"><a href="/forgot">Forgot password?</a></p>
            <p class="helper"><a href="/signup">Create a company account</a></p>
            <p class="helper"><a href="/">← Back to home</a></p>
          </section>
        </main>
        <script>
          document.querySelectorAll("[data-toggle='password']").forEach((btn) => {
            btn.addEventListener("click", () => {
              const input = btn.parentElement.querySelector("input");
              const isPassword = input.type === "password";
              input.type = isPassword ? "text" : "password";
              btn.textContent = isPassword ? "🙈" : "👁";
            });
          });
        </script>
      
    <script>
      (function() {
        const isDark = document.documentElement.classList.contains('dark-mode');
        
        window.addEventListener('DOMContentLoaded', () => {
          const btn = document.createElement('div');
          btn.className = 'floating-theme-toggle';
          btn.innerHTML = isDark ? '☀️' : '🌙';
          document.body.appendChild(btn);
          
          btn.addEventListener('click', () => {
            const isDarkNow = document.documentElement.classList.toggle('dark-mode');
            localStorage.setItem('theme', isDarkNow ? 'dark' : 'light');
            btn.innerHTML = isDarkNow ? '☀️' : '🌙';
          });
        });
      })();
    </script>
  
    <script>
      document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', (e) => {
          const btn = form.querySelector('button[type="submit"]');
          if (btn) {
            setTimeout(() => {
              btn.disabled = true;
              btn.innerHTML = '<span class="spinner"></span> Processing...';
            }, 10);
          }
        });
      });
    </script>

      </body>
    </html>
  `;
}

function renderSignup(message = "") {
  return `
    <!doctype html>
    <html lang="en">
      <head>
        <script>if(localStorage.getItem('theme')==='dark') document.documentElement.classList.add('dark-mode');</script>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Company signup</title>
        <link rel="stylesheet" href="/static/styles.css" />
      </head>
      <body>
        <main class="shell login-shell">
          <section class="panel login-panel">
            <div style="text-align: center; margin-bottom: 24px;">
              <img src="/static/logo.png" alt="Logo" style="height: 64px; border-radius: 12px; margin-bottom: 16px;">
              <h1 style="margin: 0;">Create company account</h1>
            </div>
            <p class="subtitle">Start your 30-day free trial. No credit card required.</p>
            ${message ? `<p class=\"notice\">${escapeHtml(message)}</p>` : ""}
            <form class="login-form" action="/signup" method="post">
              <label for="company_name">Company name</label>
              <input id="company_name" name="company_name" required />
              <label for="slug">Company URL (optional)</label>
              <input id="slug" name="slug" placeholder="acme" />
              <label for="name">Your name</label>
              <input id="name" name="name" required />
              <label for="email">Work email</label>
              <input id="email" name="email" type="email" required />
              <label for="allowed_domains">Allowed email domains (comma-separated)</label>
              <input id="allowed_domains" name="allowed_domains" placeholder="acme.com, acme.co" />
              <label class="checkbox">
                <input type="checkbox" name="invite_required" />
                Invite-only signup
              </label>
              <label for="password">Password</label>
              <div class="password-field">
                <input id="password" name="password" type="password" required />
                <button type="button" class="icon-button" data-toggle="password">👁</button>
              </div>
              <button type="submit">Submit signup</button>
            </form>
            <p class="helper"><a href="/login">Back to login</a></p>
          </section>
        </main>
        <script>
          document.querySelectorAll("[data-toggle='password']").forEach((btn) => {
            btn.addEventListener("click", () => {
              const input = btn.parentElement.querySelector("input");
              const isPassword = input.type === "password";
              input.type = isPassword ? "text" : "password";
              btn.textContent = isPassword ? "🙈" : "👁";
            });
          });
        </script>
      
    <script>
      (function() {
        const isDark = document.documentElement.classList.contains('dark-mode');
        
        window.addEventListener('DOMContentLoaded', () => {
          const btn = document.createElement('div');
          btn.className = 'floating-theme-toggle';
          btn.innerHTML = isDark ? '☀️' : '🌙';
          document.body.appendChild(btn);
          
          btn.addEventListener('click', () => {
            const isDarkNow = document.documentElement.classList.toggle('dark-mode');
            localStorage.setItem('theme', isDarkNow ? 'dark' : 'light');
            btn.innerHTML = isDarkNow ? '☀️' : '🌙';
          });
        });
      })();
    </script>
  
    <script>
      document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', (e) => {
          const btn = form.querySelector('button[type="submit"]');
          if (btn) {
            setTimeout(() => {
              btn.disabled = true;
              btn.innerHTML = '<span class="spinner"></span> Processing...';
            }, 10);
          }
        });
      });
    </script>

      </body>
    </html>
  `;
}



function renderCompanyAdmin(company, plans, currentUser) {
  const planOptions = plans.map(p => 
    `<option value="${p.code}" ${company.plan === p.code ? 'selected' : ''}>${escapeHtml(p.name)} (${p.price_usd})</option>`
  ).join("");
  
  const statusOptions = ['active', 'pending', 'blocked', 'suspended'].map(s => 
    `<option value="${s}" ${company.status === s ? 'selected' : ''}>${s.charAt(0).toUpperCase() + s.slice(1)}</option>`
  ).join("");
  
  const trialEnd = company.trial_ends_at ? new Date(company.trial_ends_at).toISOString().split('T')[0] : '';

  return `
    <!doctype html>
    <html lang="en">
      <head>
        <script>if(localStorage.getItem('theme')==='dark') document.documentElement.classList.add('dark-mode');</script>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Manage ${escapeHtml(company.name)} · Platform Admin</title>
        <link rel="stylesheet" href="/static/styles.css" />
      </head>
      <body>
        <main class="shell">
          <header class="topbar">
            <div>
              <h2 style="display:flex;align-items:center;gap:12px;"><img src="/static/logo.png" alt="Logo" style="height:32px;border-radius:8px;"> Manage Company</h2>
              <p>Platform Admin</p>
            </div>
            <div class="top-actions">
              <a class="ghost" href="/">Back to Dashboard</a>
              <form action="/logout" method="post">
                <button type="submit" class="ghost">Log out</button>
              </form>
            </div>
          </header>

          <section class="panel">
            <h3>${escapeHtml(company.name)}</h3>
            <form class="ticket-form" action="/admin/companies/${company.id}/action" method="post" style="max-width:600px;">
              <div>
                <label>Company Plan</label>
                <select name="plan">
                  ${planOptions}
                  <option value="pending_plan" ${company.plan === 'pending_plan' ? 'selected' : ''}>Pending Selection</option>
                </select>
              </div>
              <div>
                <label>Account Status</label>
                <select name="status">
                  ${statusOptions}
                </select>
              </div>
              <div>
                <label>Trial Ends At</label>
                <input type="date" name="trial_ends_at" value="${trialEnd}" />
                <span style="font-size:12px;color:var(--muted);">Leave blank for no trial</span>
              </div>
              
              <div class="full actions" style="display:flex; gap:16px;">
                <button type="submit" name="action" value="update" class="primary-btn">Save Changes</button>
                <button type="submit" name="action" value="delete" class="danger" onclick="return confirm('Are you sure you want to permanently delete this company and all its data? This cannot be undone.');">Delete Company</button>
              </div>
            </form>
          </section>
        </main>
      
    <script>
      (function() {
        const isDark = document.documentElement.classList.contains('dark-mode');
        
        window.addEventListener('DOMContentLoaded', () => {
          const btn = document.createElement('div');
          btn.className = 'floating-theme-toggle';
          btn.innerHTML = isDark ? '☀️' : '🌙';
          document.body.appendChild(btn);
          
          btn.addEventListener('click', () => {
            const isDarkNow = document.documentElement.classList.toggle('dark-mode');
            localStorage.setItem('theme', isDarkNow ? 'dark' : 'light');
            btn.innerHTML = isDarkNow ? '☀️' : '🌙';
          });
        });
      })();
    </script>
  
    <script>
      document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', (e) => {
          const btn = form.querySelector('button[type="submit"]');
          if (btn) {
            setTimeout(() => {
              btn.disabled = true;
              btn.innerHTML = '<span class="spinner"></span> Processing...';
            }, 10);
          }
        });
      });
    </script>

      </body>
    </html>
  `;
}

function renderBillingGate(currentUser) {
  return `
    <!doctype html>
    <html lang="en">
      <head>
        <script>if(localStorage.getItem('theme')==='dark') document.documentElement.classList.add('dark-mode');</script>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Trial expired</title>
        <link rel="stylesheet" href="/static/styles.css" />
      </head>
      <body>
        <main class="shell login-shell">
          <section class="panel login-panel">
            <div style="text-align:center;">
              <div style="font-size:48px; margin-bottom:12px;">⏳</div>
              <h1 style="margin:0 0 8px 0;">Free trial has expired</h1>
            </div>
            <p class="subtitle">Your 30-day free trial has ended.</p>
            <p class="notice">Paid plans are coming soon. We'll notify you when you can upgrade.</p>
            <a class="ghost" href="/billing" style="display:inline-block; margin-bottom:12px;">View billing page</a>
            <form action="/logout" method="post" class="helper">
              <button type="submit" class="ghost">Log out</button>
            </form>
          </section>
        </main>
      
    <script>
      (function() {
        const isDark = document.documentElement.classList.contains('dark-mode');
        
        window.addEventListener('DOMContentLoaded', () => {
          const btn = document.createElement('div');
          btn.className = 'floating-theme-toggle';
          btn.innerHTML = isDark ? '☀️' : '🌙';
          document.body.appendChild(btn);
          
          btn.addEventListener('click', () => {
            const isDarkNow = document.documentElement.classList.toggle('dark-mode');
            localStorage.setItem('theme', isDarkNow ? 'dark' : 'light');
            btn.innerHTML = isDarkNow ? '☀️' : '🌙';
          });
        });
      })();
    </script>
  
    <script>
      document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', (e) => {
          const btn = form.querySelector('button[type="submit"]');
          if (btn) {
            setTimeout(() => {
              btn.disabled = true;
              btn.innerHTML = '<span class="spinner"></span> Processing...';
            }, 10);
          }
        });
      });
    </script>

      </body>
    </html>
  `;
}

function renderCompanySettings(company, currentUser) {
  return `
    <!doctype html>
    <html lang="en">
      <head>
        <script>if(localStorage.getItem('theme')==='dark') document.documentElement.classList.add('dark-mode');</script>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Company settings</title>
        <link rel="stylesheet" href="/static/styles.css" />
      </head>
      <body>
        <main class="shell">
          <header class="topbar">
            <div>
              <h2 style="display:flex;align-items:center;gap:12px;"><img src="/static/logo.png" alt="Logo" style="height:32px;border-radius:8px;"> Company settings</h2>
              <p>${escapeHtml(company.name)} • Plan: ${escapeHtml((company.plan === 'pending_plan' || !company.plan) ? 'Not Selected' : company.plan.charAt(0).toUpperCase() + company.plan.slice(1))}</p>
            </div>
            <div class="top-actions">
              <a class="ghost" href="/admin/users">Back to users</a>
              <form action="/logout" method="post">
                <button type="submit" class="ghost">Log out</button>
              </form>
            </div>
          </header>

          <section class="panel">
            <h3>📎 Share Your Ticketing Portal</h3>
            <p class="subtitle">Share this unique URL with your employees so they can create accounts and submit tickets.</p>
            <div style="display: flex; gap: 10px; align-items: center; background: var(--surface); padding: 12px 16px; border-radius: 8px; border: 1px solid var(--border); margin: 12px 0;">
              <code id="share-url" style="flex: 1; font-size: 14px; word-break: break-all;"></code>
              <button type="button" onclick="navigator.clipboard.writeText(document.getElementById('share-url').textContent).then(()=>this.textContent='Copied!').catch(()=>{})" class="ghost" style="padding: 6px 14px; white-space: nowrap;">📋 Copy</button>
            </div>
            <p style="font-size: 13px; color: var(--muted);">Only users with approved email domains can join. Configure allowed domains below.</p>
          </section>

          <section class="panel">
            <form class="ticket-form" action="/admin/company" method="post">
              <div>
                <label for="slug">Company URL slug</label>
                <input id="slug" name="slug" value="${escapeHtml(company.slug || "")}" />
              </div>
              ${(function(){ const plan = getEffectivePlan(company); const limits = getPlanLimits(plan); return limits.customBranding; })() ? `
              <div>
                <label for="brand_color">Brand color</label>
                <input id="brand_color" name="brand_color" placeholder="#d26a2b" value="${escapeHtml(company.brand_color || "")}" />
              </div>
              <div>
                <label for="logo_url">Logo URL</label>
                <input id="logo_url" name="logo_url" placeholder="https://..." value="${escapeHtml(company.logo_url || "")}" />
              </div>
              ` : `<div class="full" style="padding:16px;background:var(--glass-bg);border-radius:12px;border:1px solid var(--border);"><p style="margin:0;font-size:14px;color:var(--muted);">🎨 Custom branding (logo & colors) is available on <strong>Growth</strong> and <strong>Enterprise</strong> plans. <a href="/billing">Upgrade</a></p></div>`}
              <div>
                <label for="allowed_domains">Allowed email domains</label>
                <input id="allowed_domains" name="allowed_domains" value="${escapeHtml(
                  company.allowed_domains || ""
                )}" />
              </div>
              <label class="checkbox">
                <input type="checkbox" name="invite_required" ${
                  company.invite_required ? "checked" : ""
                } />
                Invite-only signup
              </label>
              <div class="full actions">
                <button type="submit">Save settings</button>
              </div>
            </form>
          </section>
        </main>
        <script>
          const el = document.getElementById('share-url');
          if (el) el.textContent = window.location.origin + '/c/' + ${JSON.stringify(company.slug || "")};
        </script>
      
    <script>
      (function() {
        const isDark = document.documentElement.classList.contains('dark-mode');
        
        window.addEventListener('DOMContentLoaded', () => {
          const btn = document.createElement('div');
          btn.className = 'floating-theme-toggle';
          btn.innerHTML = isDark ? '☀️' : '🌙';
          document.body.appendChild(btn);
          
          btn.addEventListener('click', () => {
            const isDarkNow = document.documentElement.classList.toggle('dark-mode');
            localStorage.setItem('theme', isDarkNow ? 'dark' : 'light');
            btn.innerHTML = isDarkNow ? '☀️' : '🌙';
          });
        });
      })();
    </script>
  
    <script>
      document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', (e) => {
          const btn = form.querySelector('button[type="submit"]');
          if (btn) {
            setTimeout(() => {
              btn.disabled = true;
              btn.innerHTML = '<span class="spinner"></span> Processing...';
            }, 10);
          }
        });
      });
    </script>

      </body>
    </html>
  `;
}

function renderBilling(company, payments, plans, currentUser) {
  const planName = (company.plan === 'pending_plan' || !company.plan) ? 'Not Selected' : company.plan.charAt(0).toUpperCase() + company.plan.slice(1);

  const trialInfo = company.trial_ends_at
    ? (() => {
        const endsAt = new Date(company.trial_ends_at);
        const daysLeft = Math.ceil((endsAt.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
        if (daysLeft > 0) {
          return `<p style="font-size:14px;color:var(--muted);">Free trial ends: ${endsAt.toLocaleDateString()} (${daysLeft} day${daysLeft === 1 ? '' : 's'} remaining)</p>`;
        }
        return `<p style="font-size:14px;color:#dc2626;font-weight:600;">Free trial has expired.</p>`;
      })()
    : '';

  const features = {
    starter: ["Up to 5 agents", "100 tickets/month", "Email notifications", "Basic reports"],
    growth: ["Up to 20 agents", "Unlimited tickets", "Priority support", "Advanced analytics", "Custom branding"],
    enterprise: ["Unlimited agents", "Unlimited tickets", "Dedicated support", "API access", "Custom SLA rules", "Audit logs", "All Growth features"]
  };

  const planCards = plans.map(p => {
    const isCurrent = company.plan === p.code;
    const featureList = (features[p.code] || ["Full access"]).map(f => `<li>✓ ${escapeHtml(f)}</li>`).join("");
    return `
      <div class="plan-card ${isCurrent ? 'is-current' : ''}">
        ${isCurrent ? '<span class="plan-badge">Current Plan</span>' : ''}
        <h3 class="plan-title">${escapeHtml(p.name)}</h3>
        <div>
          <span class="plan-price">$${p.price_usd}</span><span class="plan-note">/mo USD</span>
        </div>
        <div class="plan-note">₱${p.price_php}/mo PHP</div>
        <ul>${featureList}</ul>
        ${isCurrent
          ? `<button disabled class="plan-cta" style="opacity:0.6;cursor:default;border:1px solid var(--border);border-radius:10px;background:var(--surface);color:var(--muted);box-shadow:none;">Active Plan</button>`
          : `<button disabled class="plan-cta" style="opacity:0.5;cursor:not-allowed;border:1px solid var(--border);border-radius:10px;background:var(--surface);color:var(--muted);box-shadow:none;">Coming Soon</button>`}
      </div>
    `;
  }).join("");

  return `
    <!doctype html>
    <html lang="en">
      <head>
        <script>if(localStorage.getItem('theme')==='dark') document.documentElement.classList.add('dark-mode');</script>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Billing & Plans</title>
        <link rel="stylesheet" href="/static/styles.css" />
      </head>
      <body>
        <main class="shell">
          <header class="topbar">
            <div>
              <h2 style="display:flex;align-items:center;gap:12px;"><img src="/static/logo.png" alt="Logo" style="height:32px;border-radius:8px;"> Billing & Plans</h2>
              <p>${escapeHtml(company.name)} • Plan: <strong>${escapeHtml(planName)}</strong></p>
              ${trialInfo}
            </div>
            <div class="top-actions">
              <a class="ghost" href="/">Back to desk</a>
              <form action="/logout" method="post">
                <button type="submit" class="ghost">Log out</button>
              </form>
            </div>
          </header>

          <section class="panel">
            <div style="text-align:center; padding:32px 16px; background:linear-gradient(135deg, var(--glass-bg), var(--surface)); border-radius:16px; border:1px solid var(--border); margin-bottom:28px;">
              <div style="font-size:48px; margin-bottom:12px;">🚧</div>
              <h3 style="margin:0 0 8px 0;">Paid Plans Coming Soon</h3>
              <p style="color:var(--muted); max-width:480px; margin:0 auto;">We're building secure payment integration. In the meantime, enjoy your 30-day free trial with full access to all Starter features.</p>
            </div>
          </section>

          <section class="panel">
            <h3>Available Plans (Preview)</h3>
            <p class="subtitle">These plans will be available once payments launch.</p>
            <div class="plan-grid" style="margin:20px 0;">
              ${planCards}
            </div>
          </section>

          <section class="panel">
            <h3>Your Trial</h3>
            <p class="subtitle">You currently have full access through your free trial.</p>
            <div style="padding:16px; background:var(--glass-bg); border-radius:10px; border:1px solid var(--border); margin-top:12px;">
              <p style="margin:0 0 4px 0;"><strong>Plan:</strong> ${escapeHtml(planName)}</p>
              ${company.trial_ends_at
                ? `<p style="margin:0;">Your free trial ${new Date(company.trial_ends_at).getTime() > Date.now() ? 'is active' : 'has ended'}. Paid billing will be available soon.</p>`
                : `<p style="margin:0;">No trial active.</p>`}
            </div>
          </section>
        </main>
      
    <script>
      (function() {
        const isDark = document.documentElement.classList.contains('dark-mode');
        
        window.addEventListener('DOMContentLoaded', () => {
          const btn = document.createElement('div');
          btn.className = 'floating-theme-toggle';
          btn.innerHTML = isDark ? '☀️' : '🌙';
          document.body.appendChild(btn);
          
          btn.addEventListener('click', () => {
            const isDarkNow = document.documentElement.classList.toggle('dark-mode');
            localStorage.setItem('theme', isDarkNow ? 'dark' : 'light');
            btn.innerHTML = isDarkNow ? '☀️' : '🌙';
          });
        });
      })();
    </script>
  
    <script>
      document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', (e) => {
          const btn = form.querySelector('button[type="submit"]');
          if (btn) {
            setTimeout(() => {
              btn.disabled = true;
              btn.innerHTML = '<span class="spinner"></span> Processing...';
            }, 10);
          }
        });
      });
    </script>

      </body>
    </html>
  `;
}

function renderCompanyLanding(company) {
  const joinForm = company.invite_required ? 
    `<p class="notice">Invite-only access is enabled. Contact your administrator.</p>` :
    `
    <div class="join-box panel">
      <h3>Join ${escapeHtml(company.name)}</h3>
      <p class="subtitle">Sign up with your approved company email.</p>
      <form action="/c/${escapeHtml(company.slug)}/join" method="post" class="login-form">
        <label>Name</label><input name="name" required />
        <label>Email</label><input type="email" name="email" placeholder="e.g. you@${escapeHtml(company.allowed_domains || 'company.com')}" required />
        <label>Password</label>
        <div class="password-field">
          <input name="password" type="password" required />
          <button type="button" class="icon-button" data-toggle="password">👁</button>
        </div>
        <button type="submit" style="margin-top: 10px;">Join Company</button>
      </form>
    </div>
    `;

  return `
    <!doctype html>
    <html lang="en">
      <head>
        <script>if(localStorage.getItem('theme')==='dark') document.documentElement.classList.add('dark-mode');</script>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>${escapeHtml(company.name)} Service Desk</title>
        <link rel="stylesheet" href="/static/styles.css" />
      </head>
      <body>
        <main class="shell login-shell" style="--brand:${company.brand_color ? escapeHtml(company.brand_color) : '#d26a2b'}">
          <section class="panel landing">
            <div class="landing-header">
              <div>
                <p class="eyebrow">${escapeHtml((company.plan === 'pending_plan' || !company.plan) ? 'Not Selected' : company.plan.charAt(0).toUpperCase() + company.plan.slice(1))} plan</p>
                <h1>${escapeHtml(company.name)} Service Desk</h1>
                <p class="subtitle">Fast, structured IT support with clear priorities, SLAs, and real-time updates.</p>
              </div>
              ${
                company.logo_url
                  ? `<img class="brand-logo" src="${escapeHtml(
                      company.logo_url
                    )}" alt="${escapeHtml(company.name)} logo" />`
                  : ""
              }
            </div>
            <div class="landing-actions">
              <a class="ghost primary" href="/login">Sign in to Existing Account</a>
              <a class="ghost" href="/">Main Page</a>
            </div>
            ${joinForm}
          </section>
        </main>
        <script>
          document.querySelectorAll("[data-toggle='password']").forEach((btn) => {
            btn.addEventListener("click", () => {
              const input = btn.parentElement.querySelector("input");
              const isPassword = input.type === "password";
              input.type = isPassword ? "text" : "password";
              btn.textContent = isPassword ? "🙈" : "👁";
            });
          });
        </script>
      
    <script>
      (function() {
        const isDark = document.documentElement.classList.contains('dark-mode');
        
        window.addEventListener('DOMContentLoaded', () => {
          const btn = document.createElement('div');
          btn.className = 'floating-theme-toggle';
          btn.innerHTML = isDark ? '☀️' : '🌙';
          document.body.appendChild(btn);
          
          btn.addEventListener('click', () => {
            const isDarkNow = document.documentElement.classList.toggle('dark-mode');
            localStorage.setItem('theme', isDarkNow ? 'dark' : 'light');
            btn.innerHTML = isDarkNow ? '☀️' : '🌙';
          });
        });
      })();
    </script>
  
    <script>
      document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', (e) => {
          const btn = form.querySelector('button[type="submit"]');
          if (btn) {
            setTimeout(() => {
              btn.disabled = true;
              btn.innerHTML = '<span class="spinner"></span> Processing...';
            }, 10);
          }
        });
      });
    </script>

      </body>
    </html>
  `;
}

function renderPlatformAdmin(companies, payments, currentUser) {
  const rows = companies
    .map(
      (company) => `
        <tr>
          <td>${escapeHtml(company.name)}</td>
          <td>${escapeHtml(company.plan)}</td>
          <td>${escapeHtml(company.status)}</td>
          <td>${company.users}</td>
          <td>${new Date(company.created_at).toLocaleString()}</td>
          <td>
            <form action="/platform/companies/${company.id}/approve" method="post" class="inline-form">
              <button type="submit">Approve</button>
            </form>
            <form action="/platform/companies/${company.id}/suspend" method="post" class="inline-form">
              <button type="submit" class="danger">Suspend</button>
            </form>
          </td>
        </tr>
      `
    )
    .join("");

  const paymentRows = payments
    .map(
      (payment) => `
        <tr>
          <td>${escapeHtml(payment.company_name)}</td>
          <td>${escapeHtml(payment.method)}</td>
          <td>${escapeHtml(payment.reference || "")}</td>
          <td>${escapeHtml(payment.amount || "")}</td>
          <td>${escapeHtml(payment.status)}</td>
          <td>${new Date(payment.created_at).toLocaleString()}</td>
          <td>
            <form action="/billing/verify" method="post" class="inline-form">
              <input type="hidden" name="request_id" value="${payment.id}" />
              <button type="submit">Mark paid</button>
            </form>
          </td>
        </tr>
      `
    )
    .join("");

  return `
    <!doctype html>
    <html lang="en">
      <head>
        <script>if(localStorage.getItem('theme')==='dark') document.documentElement.classList.add('dark-mode');</script>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Platform Admin</title>
        <link rel="stylesheet" href="/static/styles.css" />
      </head>
      <body>
        <main class="shell">
          <header class="topbar">
            <div>
              <h2 style="display:flex;align-items:center;gap:12px;"><img src="/static/logo.png" alt="Logo" style="height:32px;border-radius:8px;"> Platform Admin</h2>
              <p>Signed in as ${escapeHtml(currentUser.name)}</p>
            </div>
            <div class="top-actions">
              <form action="/logout" method="post">
                <button type="submit" class="ghost">Log out</button>
              </form>
            </div>
          </header>

          <section class="panel">
            <h3>Companies</h3>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Plan</th>
                    <th>Status</th>
                    <th>Users</th>
                    <th>Created</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  ${rows || "<tr><td colspan=\"6\">No companies yet.</td></tr>"}
                </tbody>
              </table>
            </div>
          </section>

          <section class="panel">
            <h3>Payment requests</h3>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Company</th>
                    <th>Method</th>
                    <th>Reference</th>
                    <th>Amount</th>
                    <th>Status</th>
                    <th>Created</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  ${paymentRows || "<tr><td colspan=\"7\">No payment requests yet.</td></tr>"}
                </tbody>
              </table>
            </div>
          </section>
        </main>
      
    <script>
      (function() {
        const isDark = document.documentElement.classList.contains('dark-mode');
        
        window.addEventListener('DOMContentLoaded', () => {
          const btn = document.createElement('div');
          btn.className = 'floating-theme-toggle';
          btn.innerHTML = isDark ? '☀️' : '🌙';
          document.body.appendChild(btn);
          
          btn.addEventListener('click', () => {
            const isDarkNow = document.documentElement.classList.toggle('dark-mode');
            localStorage.setItem('theme', isDarkNow ? 'dark' : 'light');
            btn.innerHTML = isDarkNow ? '☀️' : '🌙';
          });
        });
      })();
    </script>
  
    <script>
      document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', (e) => {
          const btn = form.querySelector('button[type="submit"]');
          if (btn) {
            setTimeout(() => {
              btn.disabled = true;
              btn.innerHTML = '<span class="spinner"></span> Processing...';
            }, 10);
          }
        });
      });
    </script>

      </body>
    </html>
  `;
}

function renderForgot(message = "") {
  return `
    <!doctype html>
    <html lang="en">
      <head>
        <script>if(localStorage.getItem('theme')==='dark') document.documentElement.classList.add('dark-mode');</script>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Reset password</title>
        <link rel="stylesheet" href="/static/styles.css" />
      </head>
      <body>
        <main class="shell login-shell">
          <section class="panel login-panel">
            <h1>Reset password</h1>
            <p class="subtitle">Enter your email to receive a reset link.</p>
            ${message ? `<p class=\"notice\">${escapeHtml(message)}</p>` : ""}
            <form class="login-form" action="/forgot" method="post">
              <label for="email">Email</label>
              <input id="email" name="email" type="email" required />
              <button type="submit">Send reset link</button>
            </form>
            <p class="helper"><a href="/login">Back to login</a></p>
          </section>
        </main>
      
    <script>
      (function() {
        const isDark = document.documentElement.classList.contains('dark-mode');
        
        window.addEventListener('DOMContentLoaded', () => {
          const btn = document.createElement('div');
          btn.className = 'floating-theme-toggle';
          btn.innerHTML = isDark ? '☀️' : '🌙';
          document.body.appendChild(btn);
          
          btn.addEventListener('click', () => {
            const isDarkNow = document.documentElement.classList.toggle('dark-mode');
            localStorage.setItem('theme', isDarkNow ? 'dark' : 'light');
            btn.innerHTML = isDarkNow ? '☀️' : '🌙';
          });
        });
      })();
    </script>
  
    <script>
      document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', (e) => {
          const btn = form.querySelector('button[type="submit"]');
          if (btn) {
            setTimeout(() => {
              btn.disabled = true;
              btn.innerHTML = '<span class="spinner"></span> Processing...';
            }, 10);
          }
        });
      });
    </script>

      </body>
    </html>
  `;
}

function renderInviteAccept(token, message = "") {
  return `
    <!doctype html>
    <html lang="en">
      <head>
        <script>if(localStorage.getItem('theme')==='dark') document.documentElement.classList.add('dark-mode');</script>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Accept Invite</title>
        <link rel="stylesheet" href="/static/styles.css" />
      </head>
      <body>
        <main class="shell login-shell">
          <section class="panel login-panel">
            <div style="text-align: center; margin-bottom: 24px;">
              <img src="/static/logo.png" alt="Logo" style="height: 64px; border-radius: 12px; margin-bottom: 16px;">
              <h1 style="margin: 0;">Accept Invitation</h1>
            </div>
            ${message ? `<p class="notice">${escapeHtml(message)}</p>` : ""}
            <form action="/invite/${escapeHtml(token)}" method="post" class="login-form">
              <label for="name">Your Name</label>
              <input type="text" id="name" name="name" required />
              <label for="password">Choose Password</label>
              <div class="password-field">
                <input type="password" id="password" name="password" required />
                <button type="button" class="icon-button" data-toggle="password">👁</button>
              </div>
              <button type="submit">Join Team</button>
            </form>
          </section>
        </main>
        <script>
          document.querySelectorAll("[data-toggle='password']").forEach((btn) => {
            btn.addEventListener("click", () => {
              const input = btn.parentElement.querySelector("input");
              const isPassword = input.type === "password";
              input.type = isPassword ? "text" : "password";
              btn.textContent = isPassword ? "🙈" : "👁";
            });
          });
        </script>
      
    <script>
      document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', (e) => {
          const btn = form.querySelector('button[type="submit"]');
          if (btn) {
            setTimeout(() => {
              btn.disabled = true;
              btn.innerHTML = '<span class="spinner"></span> Processing...';
            }, 10);
          }
        });
      });
    </script>

      </body>
    </html>
  `;
}

function renderReset(token, error = "") {
  return `
    <!doctype html>
    <html lang="en">
      <head>
        <script>if(localStorage.getItem('theme')==='dark') document.documentElement.classList.add('dark-mode');</script>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Choose new password</title>
        <link rel="stylesheet" href="/static/styles.css" />
      </head>
      <body>
        <main class="shell login-shell">
          <section class="panel login-panel">
            <h1>Choose a new password</h1>
            ${error ? `<p class=\"error\">${escapeHtml(error)}</p>` : ""}
            <form class="login-form" action="/reset/${escapeHtml(token)}" method="post">
              <label for="password">New password</label>
              <div class="password-field">
                <input id="password" name="password" type="password" required />
                <button type="button" class="icon-button" data-toggle="password">👁</button>
              </div>
              <button type="submit">Update password</button>
            </form>
            <p class="helper"><a href="/login">Back to login</a></p>
          </section>
        </main>
        <script>
          document.querySelectorAll("[data-toggle='password']").forEach((btn) => {
            btn.addEventListener("click", () => {
              const input = btn.parentElement.querySelector("input");
              const isPassword = input.type === "password";
              input.type = isPassword ? "text" : "password";
              btn.textContent = isPassword ? "🙈" : "👁";
            });
          });
        </script>
      
    <script>
      (function() {
        const isDark = document.documentElement.classList.contains('dark-mode');
        
        window.addEventListener('DOMContentLoaded', () => {
          const btn = document.createElement('div');
          btn.className = 'floating-theme-toggle';
          btn.innerHTML = isDark ? '☀️' : '🌙';
          document.body.appendChild(btn);
          
          btn.addEventListener('click', () => {
            const isDarkNow = document.documentElement.classList.toggle('dark-mode');
            localStorage.setItem('theme', isDarkNow ? 'dark' : 'light');
            btn.innerHTML = isDarkNow ? '☀️' : '🌙';
          });
        });
      })();
    </script>
  
    <script>
      document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', (e) => {
          const btn = form.querySelector('button[type="submit"]');
          if (btn) {
            setTimeout(() => {
              btn.disabled = true;
              btn.innerHTML = '<span class="spinner"></span> Processing...';
            }, 10);
          }
        });
      });
    </script>

      </body>
    </html>
  `;
}

function renderUserAdmin(users, invites, currentUser) {
  const rows = users
    .map(
      (user) => `
        <tr>
          <td>${escapeHtml(user.name)}</td>
          <td>${escapeHtml(user.email || "")}</td>
          <td>${escapeHtml(user.role)}</td>
          <td>
            <form action="/admin/users/${user.id}/reset" method="post" class="inline-form">
              <div class="password-field compact">
                <input name="password" type="password" placeholder="New password" required />
                <button type="button" class="icon-button" data-toggle="password">👁</button>
              </div>
              <button type="submit">Reset</button>
            </form>
          </td>
        </tr>
      `
    )
    .join("");

  return `
    <!doctype html>
    <html lang="en">
      <head>
        <script>if(localStorage.getItem('theme')==='dark') document.documentElement.classList.add('dark-mode');</script>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>User Admin</title>
        <link rel="stylesheet" href="/static/styles.css" />
      </head>
      <body>
        <main class="shell">
          <header class="topbar">
            <div>
              <h2 style="display:flex;align-items:center;gap:12px;"><img src="/static/logo.png" alt="Logo" style="height:32px;border-radius:8px;"> User Admin</h2>
              <p>Signed in as ${escapeHtml(currentUser.name)} (${escapeHtml(currentUser.role)})</p>
            </div>
            <div class="top-actions">
              <a class="ghost" href="/">Back to desk</a>
              <form action="/logout" method="post">
                <button type="submit" class="ghost">Log out</button>
              </form>
            </div>
          </header>

          <section class="panel">
            <h3>Create user</h3>
            <form class="ticket-form" action="/admin/users" method="post">
              <div>
                <label for="name">Name</label>
                <input id="name" name="name" required />
              </div>
              <div>
                <label for="email">Email</label>
                <input id="email" name="email" type="email" required />
              </div>
              <div>
                <label for="role">Role</label>
                <select id="role" name="role">
                  <option value="requester">Requester</option>
                  <option value="agent">Agent</option>
                </select>
              </div>
              <div>
                <label for="password">Password</label>
                <div class="password-field">
                  <input id="password" name="password" type="password" required />
                  <button type="button" class="icon-button" data-toggle="password">👁</button>
                </div>
              </div>
              <div class="full actions">
                <button type="submit">Create user</button>
              </div>
            </form>
          </section>

          <section class="panel">
            <h3>Send invite</h3>
            <form class="ticket-form" action="/admin/invites" method="post">
              <div>
                <label for="invite-email">Email</label>
                <input id="invite-email" name="email" type="email" required />
              </div>
              <div>
                <label for="invite-role">Role</label>
                <select id="invite-role" name="role">
                  <option value="requester">Requester</option>
                  <option value="agent">Agent</option>
                </select>
              </div>
              <div class="full actions">
                <button type="submit">Send invite</button>
              </div>
            </form>
          </section>

          <section class="panel">
            <h3>Users</h3>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Reset password</th>
                  </tr>
                </thead>
                <tbody>
                  ${rows}
                </tbody>
              </table>
            </div>
          </section>

          <section class="panel">
            <h3>Invites</h3>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Expires</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  ${renderInviteRows(invites)}
                </tbody>
              </table>
            </div>
          </section>

          <section class="panel">
            <h3>Company settings</h3>
            <p class="subtitle">Manage invite rules, branding, and URL.</p>
            <a class="ghost" href="/admin/company">Open company settings</a>
          </section>
        </main>
        <script>
          document.querySelectorAll("[data-toggle='password']").forEach((btn) => {
            btn.addEventListener("click", () => {
              const input = btn.parentElement.querySelector("input");
              const isPassword = input.type === "password";
              input.type = isPassword ? "text" : "password";
              btn.textContent = isPassword ? "🙈" : "👁";
            });
          });
        </script>
      
    <script>
      (function() {
        const isDark = document.documentElement.classList.contains('dark-mode');
        
        window.addEventListener('DOMContentLoaded', () => {
          const btn = document.createElement('div');
          btn.className = 'floating-theme-toggle';
          btn.innerHTML = isDark ? '☀️' : '🌙';
          document.body.appendChild(btn);
          
          btn.addEventListener('click', () => {
            const isDarkNow = document.documentElement.classList.toggle('dark-mode');
            localStorage.setItem('theme', isDarkNow ? 'dark' : 'light');
            btn.innerHTML = isDarkNow ? '☀️' : '🌙';
          });
        });
      })();
    </script>
  
    <script>
      document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', (e) => {
          const btn = form.querySelector('button[type="submit"]');
          if (btn) {
            setTimeout(() => {
              btn.disabled = true;
              btn.innerHTML = '<span class="spinner"></span> Processing...';
            }, 10);
          }
        });
      });
    </script>

      </body>
    </html>
  `;
}

function renderAdminPlans(plans, currentUser) {
  const rows = plans.map(p => `
    <tr>
      <td><strong>${escapeHtml(p.name)}</strong></td>
      <td>
        <form action="/admin/plans/${p.id}" method="post" style="display: flex; gap: 10px; align-items: center;">
          $<input type="number" name="price_usd" value="${p.price_usd}" style="width: 80px;" required />
          ₱<input type="number" name="price_php" value="${p.price_php}" style="width: 100px;" required />
          <button type="submit" style="padding: 6px 12px; font-size: 12px;">Save</button>
        </form>
      </td>
    </tr>
  `).join("");

  return `
    <!doctype html>
    <html lang="en">
      <head>
        <script>if(localStorage.getItem('theme')==='dark') document.documentElement.classList.add('dark-mode');</script>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Manage Plans</title>
        <link rel="stylesheet" href="/static/styles.css" />
      </head>
      <body>
        <main class="shell">
          <header class="topbar">
            <div>
              <h2 style="display:flex;align-items:center;gap:12px;"><img src="/static/logo.png" alt="Logo" style="height:32px;border-radius:8px;"> Manage Pricing Plans</h2>
              <p>Platform Admin Settings</p>
            </div>
            <div class="top-actions">
              <a class="ghost" href="/">Back to desk</a>
            </div>
          </header>
          <section class="panel">
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Plan Name</th>
                    <th>Pricing (USD / PHP)</th>
                  </tr>
                </thead>
                <tbody>
                  ${rows}
                </tbody>
              </table>
            </div>
          </section>
        </main>
      
    <script>
      (function() {
        const isDark = document.documentElement.classList.contains('dark-mode');
        
        window.addEventListener('DOMContentLoaded', () => {
          const btn = document.createElement('div');
          btn.className = 'floating-theme-toggle';
          btn.innerHTML = isDark ? '☀️' : '🌙';
          document.body.appendChild(btn);
          
          btn.addEventListener('click', () => {
            const isDarkNow = document.documentElement.classList.toggle('dark-mode');
            localStorage.setItem('theme', isDarkNow ? 'dark' : 'light');
            btn.innerHTML = isDarkNow ? '☀️' : '🌙';
          });
        });
      })();
    </script>
  
    <script>
      document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', (e) => {
          const btn = form.querySelector('button[type="submit"]');
          if (btn) {
            setTimeout(() => {
              btn.disabled = true;
              btn.innerHTML = '<span class="spinner"></span> Processing...';
            }, 10);
          }
        });
      });
    </script>

      </body>
    </html>
  `;
}

function renderInviteRows(invites) {
  if (!invites.length) {
    return "<tr><td colspan=\"4\">No invites yet.</td></tr>";
  }

  return invites
    .map(
      (invite) => `
        <tr>
          <td>${escapeHtml(invite.email || "")}</td>
          <td>${escapeHtml(invite.role)}</td>
          <td>${new Date(invite.expires_at).toLocaleDateString()}</td>
          <td>${invite.used_at ? "Used" : "Active"}</td>
        </tr>
      `
    )
    .join("");
}

function renderAuditLogs(logs, currentUser) {
  const rows = logs.map(log => `
    <tr>
      <td>${new Date(log.created_at).toLocaleString()}</td>
      <td>${escapeHtml(log.actor_name || 'System')}</td>
      <td><span style="display:inline-block;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600;color:white;background:var(--accent);">${escapeHtml(log.action)}</span></td>
      <td>${escapeHtml(log.entity_type)}</td>
      <td>${escapeHtml(log.details || '')}</td>
    </tr>
  `).join('');
  return `
    <!doctype html>
    <html lang="en">
      <head>
        <script>if(localStorage.getItem('theme')==='dark') document.documentElement.classList.add('dark-mode');</script>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Audit Logs</title>
        <link rel="stylesheet" href="/static/styles.css" />
      </head>
      <body>
        <main class="shell">
          <header class="topbar">
            <div>
              <h2 style="display:flex;align-items:center;gap:12px;"><img src="/static/logo.png" alt="Logo" style="height:32px;border-radius:8px;"> Audit Logs</h2>
              <p>Signed in as ${escapeHtml(currentUser.name)} (${escapeHtml(currentUser.role)})</p>
            </div>
            <div class="top-actions">
              <a class="ghost" href="/">Back to desk</a>
              <form action="/logout" method="post">
                <button type="submit" class="ghost">Log out</button>
              </form>
            </div>
          </header>
          <section class="panel">
            <h3>🔍 Activity Log (Last 100 Events)</h3>
            <p class="subtitle">Enterprise-only feature — full audit trail of all actions in your company.</p>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr><th>Time</th><th>Actor</th><th>Action</th><th>Entity</th><th>Details</th></tr>
                </thead>
                <tbody>
                  ${rows || '<tr><td colspan="5" class="empty">No audit logs yet.</td></tr>'}
                </tbody>
              </table>
            </div>
          </section>
        </main>
        <script>
          (function() {
            const isDark = document.documentElement.classList.contains('dark-mode');
            window.addEventListener('DOMContentLoaded', () => {
              const btn = document.createElement('div');
              btn.className = 'floating-theme-toggle';
              btn.innerHTML = isDark ? '☀️' : '🌙';
              document.body.appendChild(btn);
              btn.addEventListener('click', () => {
                const isDarkNow = document.documentElement.classList.toggle('dark-mode');
                localStorage.setItem('theme', isDarkNow ? 'dark' : 'light');
                btn.innerHTML = isDarkNow ? '☀️' : '🌙';
              });
            });
          })();
        </script>
      
    <script>
      document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', (e) => {
          const btn = form.querySelector('button[type="submit"]');
          if (btn) {
            setTimeout(() => {
              btn.disabled = true;
              btn.innerHTML = '<span class="spinner"></span> Processing...';
            }, 10);
          }
        });
      });
    </script>

      </body>
    </html>
  `;
}


function renderReports(metrics, currentUser) {
  const rows = metrics.topPriorities
    .map((row) => `<li>${escapeHtml(row.priority)}: ${row.count}</li>`)
    .join("");

  return `
    <!doctype html>
    <html lang="en">
      <head>
        <script>if(localStorage.getItem('theme')==='dark') document.documentElement.classList.add('dark-mode');</script>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Reports</title>
        <link rel="stylesheet" href="/static/styles.css" />
      </head>
      <body>
        <main class="shell">
          <header class="topbar">
            <div>
              <h2 style="display:flex;align-items:center;gap:12px;"><img src="/static/logo.png" alt="Logo" style="height:32px;border-radius:8px;"> Reports</h2>
              <p>Signed in as ${escapeHtml(currentUser.name)} (${escapeHtml(currentUser.role)})</p>
            </div>
            <div class="top-actions">
              <a class="ghost" href="/">Back to desk</a>
              <form action="/logout" method="post">
                <button type="submit" class="ghost">Log out</button>
              </form>
            </div>
          </header>

          <section class="panel">
            <div class="report-grid">
              <div class="report-card">
                <h4>Total tickets</h4>
                <p>${metrics.total}</p>
              </div>
              <div class="report-card">
                <h4>Open</h4>
                <p>${metrics.open}</p>
              </div>
              <div class="report-card">
                <h4>In progress</h4>
                <p>${metrics.inProgress}</p>
              </div>
              <div class="report-card">
                <h4>Resolved</h4>
                <p>${metrics.resolved}</p>
              </div>
              <div class="report-card">
                <h4>Overdue SLA</h4>
                <p>${metrics.overdue}</p>
              </div>
            </div>
          </section>

          <section class="panel">
            <h3>Tickets by priority</h3>
            <ul class="report-list">
              ${rows}
            </ul>
          </section>

          ${metrics.advancedData ? `
          <section class="panel">
            <h3>📊 Advanced Analytics</h3>
            <div class="report-grid">
              <div class="report-card">
                <h4>Avg Resolution Time</h4>
                <p style="font-size:28px;">${metrics.advancedData.avgResolutionHours}h</p>
              </div>
            </div>
          </section>

          <section class="panel">
            <h3>📈 Tickets Created (Last 14 Days)</h3>
            <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(40px,1fr));gap:4px;align-items:end;height:120px;padding:16px 0;">
              ${(function() {
                const days = metrics.advancedData.ticketsByDay.slice().reverse();
                const maxCount = Math.max(...days.map(d => d.count), 1);
                return days.map(d => {
                  const pct = (d.count / maxCount) * 100;
                  return '<div style="display:flex;flex-direction:column;align-items:center;height:100%;justify-content:flex-end;">'
                    + '<span style="font-size:10px;color:var(--muted);margin-bottom:4px;">' + d.count + '</span>'
                    + '<div style="width:100%;min-height:4px;height:' + pct + '%;background:var(--accent);border-radius:4px 4px 0 0;"></div>'
                    + '<span style="font-size:9px;color:var(--muted);margin-top:4px;white-space:nowrap;">' + d.day.slice(5) + '</span>'
                    + '</div>';
                }).join('');
              })()}
            </div>
          </section>

          <section class="panel">
            <h3>👥 Agent Performance</h3>
            <div class="table-wrap">
              <table>
                <thead><tr><th>Agent</th><th>Assigned</th><th>Resolved</th><th>Rate</th></tr></thead>
                <tbody>
                  ${metrics.advancedData.agentPerformance.map(a => '<tr>'
                    + '<td>' + escapeHtml(a.name) + '</td>'
                    + '<td>' + a.assigned_count + '</td>'
                    + '<td>' + a.resolved_count + '</td>'
                    + '<td>' + (a.assigned_count > 0 ? Math.round((a.resolved_count / a.assigned_count) * 100) : 0) + '%</td>'
                    + '</tr>').join('')}
                </tbody>
              </table>
            </div>
          </section>
          ` : `<section class="panel" style="text-align:center;padding:40px;"><h3>📊 Advanced Analytics</h3><p style="color:var(--muted);">Advanced analytics are available on Growth and Enterprise plans.</p><a href="/billing" class="primary-btn" style="display:inline-block;margin-top:16px;">Upgrade Plan</a></section>`}
        </main>
      
    <script>
      (function() {
        const isDark = document.documentElement.classList.contains('dark-mode');
        
        window.addEventListener('DOMContentLoaded', () => {
          const btn = document.createElement('div');
          btn.className = 'floating-theme-toggle';
          btn.innerHTML = isDark ? '☀️' : '🌙';
          document.body.appendChild(btn);
          
          btn.addEventListener('click', () => {
            const isDarkNow = document.documentElement.classList.toggle('dark-mode');
            localStorage.setItem('theme', isDarkNow ? 'dark' : 'light');
            btn.innerHTML = isDarkNow ? '☀️' : '🌙';
          });
        });
      })();
    </script>
  
    <script>
      document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', (e) => {
          const btn = form.querySelector('button[type="submit"]');
          if (btn) {
            setTimeout(() => {
              btn.disabled = true;
              btn.innerHTML = '<span class="spinner"></span> Processing...';
            }, 10);
          }
        });
      });
    </script>

      </body>
    </html>
  `;
}

async function notifyTicketCreated(id, title, description, priority, actor) {
  sendTicketNotification({
    subject: `New ticket #${id}: ${title}`,
    text: `New ticket created by ${actor.name} (${actor.role})\nPriority: ${priority}\n\n${description}`,
  });
}

async function notifyTicketCommented(id, body, actor) {
  sendTicketNotification({
    subject: `Ticket #${id} updated`,
    text: `${actor.name} added a comment:\n${body}`,
  });
}

async function notifyTicketStatus(id, status, actor) {
  sendTicketNotification({
    subject: `Ticket #${id} status changed`,
    text: `${actor.name} set status to ${status}.`,
  });
}

async function notifyTicketPriority(id, priority, actor) {
  sendTicketNotification({
    subject: `Ticket #${id} priority updated`,
    text: `${actor.name} set priority to ${priority}.`,
  });
}

async function notifyTicketAssigned(id, assigneeId, actor) {
  const assignee = assigneeId
    ? await db.prepare("SELECT name FROM users WHERE id = ?").get(assigneeId)
    : null;
  sendTicketNotification({
    subject: `Ticket #${id} assigned`,
    text: `${actor.name} assigned ticket to ${assignee ? assignee.name : "Unassigned"}.`,
  });
}

async function notifyTicketSla(id, slaDueAt, actor) {
  sendTicketNotification({
    subject: `Ticket #${id} SLA updated`,
    text: `${actor.name} set SLA due to ${new Date(slaDueAt).toLocaleString()}.`,
  });
}

function renderComments(comments = []) {
  if (!comments.length) {
    return "<li class=\"empty\">No updates yet.</li>";
  }

  return comments
    .map(
      (comment) => `
        <li>
          <p>${escapeHtml(comment.body)}</p>
          <span>${escapeHtml(comment.author)} • ${new Date(
            comment.created_at
          ).toLocaleString()}</span>
        </li>
      `
    )
    .join("");
}

function renderAttachments(attachments = [], ticketId = 0) {
  if (!attachments.length) {
    return "<li class=\"empty\">No files uploaded.</li>";
  }

  const imageExts = [".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg"];

  return attachments
    .map((attachment) => {
      const ext = (attachment.original_name || "").toLowerCase().replace(/.*(\.\w+)$/, "$1");
      const isImage = imageExts.includes(ext);
      const url = `/uploads/${encodeURIComponent(attachment.stored_name)}`;
      const deleteBtn = `<form action="/tickets/${ticketId}/attachments/${attachment.id}/delete" method="post" style="display:inline;" onsubmit="return confirm('Delete this file?')"><button type="submit" style="background:none;border:none;color:#ef4444;cursor:pointer;font-size:12px;padding:2px 6px;">✕ Remove</button></form>`;

      if (isImage) {
        return `
          <li style="margin-bottom: 10px;">
            <div style="border: 1px solid var(--border); border-radius: 8px; overflow: hidden; max-width: 400px; position: relative;">
              <img src="${url}" alt="${escapeHtml(attachment.original_name)}" style="width: 100%; display: block; cursor: pointer;" onclick="this.requestFullscreen ? this.requestFullscreen() : null" />
            </div>
            <div style="display: flex; align-items: center; gap: 8px; margin-top: 4px;">
              <span style="font-size: 12px; color: var(--muted);">${escapeHtml(attachment.original_name)} · ${formatBytes(attachment.size_bytes)}</span>
              ${deleteBtn}
            </div>
          </li>
        `;
      }

      return `
        <li style="display: flex; align-items: center; gap: 8px;">
          <a href="${url}" target="_blank" rel="noreferrer">📄 ${escapeHtml(attachment.original_name)}</a>
          <span>${formatBytes(attachment.size_bytes)}</span>
          ${deleteBtn}
        </li>
      `;
    })
    .join("");
}

function renderOption(value, current, label = value) {
  return `<option value="${escapeHtml(value)}" ${value === current ? "selected" : ""}>${escapeHtml(label)}</option>`;
}

function renderSuperAdminDashboard(data, currentUser) {
  const { companies, totalTickets, resolvedTickets, totalUsers, freeTrialUsers, totalIncomeUsd, activeCompanies, trialCompanies, auditLogs, payments } = data;

  const paymentRows = (payments || []).map(p => `
    <tr>
      <td>${escapeHtml(p.company_name)}</td>
      <td>${escapeHtml(p.method)}</td>
      <td>${escapeHtml(p.reference || "")}</td>
      <td>${escapeHtml(p.amount || "")}</td>
      <td>${escapeHtml(p.status)}</td>
      <td>${new Date(p.created_at).toLocaleString()}</td>
      <td>
        ${p.status === 'pending' ? `
        <form action="/billing/verify" method="post" class="inline-form">
          <input type="hidden" name="request_id" value="${p.id}" />
          <button type="submit" style="padding:4px 8px;font-size:12px;">Verify Payment</button>
        </form>
        ` : '—'}
      </td>
    </tr>
  `).join("");

  const companyRows = companies.map(c => {
    const statusColor = c.status === 'active' ? '#10b981' : c.status === 'pending' ? '#f59e0b' : '#ef4444';
    const trialLabel = c.trial_ends_at ? new Date(c.trial_ends_at).toLocaleDateString() : "—";
    return `
      <tr>
        <td><strong>${escapeHtml(c.name)}</strong><br><span style="font-size:12px; color: var(--muted);">${escapeHtml(c.slug)}</span></td>
        <td><span class="badge" style="background:${statusColor}; color:white;">${escapeHtml(c.status)}</span></td>
        <td>${escapeHtml((c.plan === 'pending_plan' || !c.plan) ? 'Not Selected' : c.plan.charAt(0).toUpperCase() + c.plan.slice(1))}</td>
        <td>${c.user_count}</td>
        <td>${c.ticket_count}</td>
        <td>${trialLabel}</td>
        <td>${new Date(c.created_at).toLocaleDateString()}</td>
        <td><a href="/admin/companies/${c.id}" class="ghost" style="padding:4px 8px;font-size:12px;">Manage</a></td>
      </tr>
    `;
  }).join("");

  const logRows = auditLogs.map(l => `
    <tr>
      <td style="font-size:13px;">${escapeHtml(l.actor_name || 'System')}</td>
      <td style="font-size:13px;"><code>${escapeHtml(l.action)}</code></td>
      <td style="font-size:12px; max-width:250px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(l.details || '')}</td>
      <td style="font-size:12px; color:var(--muted);">${new Date(l.created_at).toLocaleString()}</td>
    </tr>
  `).join("");

  return `
    <!doctype html>
    <html lang="en">
      <head>
        <script>if(localStorage.getItem('theme')==='dark') document.documentElement.classList.add('dark-mode');</script>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Platform Admin · Service Desk</title>
        <link rel="stylesheet" href="/static/styles.css" />
      </head>
      <body>
        <main class="shell">
          <header class="topbar">
            <div>
              <h2 style="display:flex;align-items:center;gap:12px;"><img src="/static/logo.png" alt="Logo" style="height:32px;border-radius:8px;"> ⚙️ Platform Admin</h2>
              <p>Signed in as ${escapeHtml(currentUser.name)} (super_admin)</p>
            </div>
            <div class="top-actions">
              <a class="ghost" href="/admin/plans">Manage Plans</a>
              <form action="/logout" method="post">
                <button type="submit" class="ghost">Log out</button>
              </form>
            </div>
          </header>

          <section class="hero">
            <div>
              <p class="eyebrow">Real-time Overview</p>
              <h1>Platform Dashboard</h1>
              <p class="subtitle">Monitor all companies, subscriptions, and system activity.</p>
            </div>
            <div class="stats" style="display:flex; flex-wrap:wrap; gap:32px;">
              <div>
                <span class="stat">$${totalIncomeUsd || 0}</span>
                <span class="label">Total Income</span>
              </div>
              <div>
                <span class="stat">${companies.length}</span>
                <span class="label">Companies</span>
              </div>
              <div>
                <span class="stat">${activeCompanies}</span>
                <span class="label">Active Companies</span>
              </div>
              <div>
                <span class="stat">${freeTrialUsers}</span>
                <span class="label">Free Trial Users</span>
              </div>
              <div>
                <span class="stat">${totalUsers}</span>
                <span class="label">Total Users</span>
              </div>
              <div>
                <span class="stat">${resolvedTickets} / ${totalTickets}</span>
                <span class="label">Resolved Tickets</span>
              </div>
            </div>
          </section>

          <section class="panel">
            <h2 style="display:flex;align-items:center;gap:12px;"><img src="/static/logo.png" alt="Logo" style="height:32px;border-radius:8px;"> All Companies</h2>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Company</th>
                    <th>Status</th>
                    <th>Plan</th>
                    <th>Users</th>
                    <th>Tickets</th>
                    <th>Trial Ends</th>
                    <th>Created</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  ${companyRows || "<tr><td colspan='8'>No companies found.</td></tr>"}
                </tbody>
              </table>
            </div>
          </section>

          <section class="panel">
            <h3>Recent Payment Requests</h3>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Company</th>
                    <th>Method</th>
                    <th>Reference</th>
                    <th>Amount</th>
                    <th>Status</th>
                    <th>Date</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  ${paymentRows || "<tr><td colspan='7'>No recent payment requests.</td></tr>"}
                </tbody>
              </table>
            </div>
          </section>

          <section class="panel">
            <h2 style="display:flex;align-items:center;gap:12px;"><img src="/static/logo.png" alt="Logo" style="height:32px;border-radius:8px;"> Recent Audit Log</h2>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Action</th>
                    <th>Details</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  ${logRows || "<tr><td colspan='4'>No activity yet.</td></tr>"}
                </tbody>
              </table>
            </div>
          </section>
        </main>
      
    <script>
      (function() {
        const isDark = document.documentElement.classList.contains('dark-mode');
        
        window.addEventListener('DOMContentLoaded', () => {
          const btn = document.createElement('div');
          btn.className = 'floating-theme-toggle';
          btn.innerHTML = isDark ? '☀️' : '🌙';
          document.body.appendChild(btn);
          
          btn.addEventListener('click', () => {
            const isDarkNow = document.documentElement.classList.toggle('dark-mode');
            localStorage.setItem('theme', isDarkNow ? 'dark' : 'light');
            btn.innerHTML = isDarkNow ? '☀️' : '🌙';
          });
        });
      })();
    </script>
  
    <script>
      document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', (e) => {
          const btn = form.querySelector('button[type="submit"]');
          if (btn) {
            setTimeout(() => {
              btn.disabled = true;
              btn.innerHTML = '<span class="spinner"></span> Processing...';
            }, 10);
          }
        });
      });
    </script>

      </body>
    </html>
  `;
}

function renderPublicLanding() {
  return `
    <!doctype html>
    <html lang="en">
      <head>
        <script>if(localStorage.getItem('theme')==='dark') document.documentElement.classList.add('dark-mode');</script>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Service Desk - Modern Ticketing</title>
        <link rel="stylesheet" href="/static/styles.css" />
      </head>
      <body>
        <main class="public-landing">
          <nav class="public-nav">
            <div class="logo" style="display:flex;align-items:center;gap:12px;"><img src="/static/logo.png" alt="Logo" style="height:36px;border-radius:8px;">Service Desk</div>
            <div class="nav-links">
              <a class="ghost" href="/login">Sign in</a>
              <a class="ghost" href="/signup">Pricing</a>
            </div>
          </nav>
          <header class="public-hero">
            <div class="hero-content">
              <p class="eyebrow">AI-powered ticketing for modern IT</p>
              <h1>Run support like a product, not a queue.</h1>
              <p>Intelligent triage, clean handoffs, and clear accountability for every request. Give your team a branded help desk that looks as sharp as it performs.</p>
              <div class="cta-group">
                <a href="/signup" class="primary-btn glow-btn" style="text-decoration:none; display:inline-block;">Start Free Trial</a>
                <p class="demo-note">30 days free. No credit card required.</p>
              </div>
            </div>
            <div class="hero-image-wrapper">
              <div class="glass-mockup">
                <div class="mockup-header">
                  <span class="dot"></span>
                  <span class="dot"></span>
                  <span class="dot"></span>
                </div>
                <div class="mockup-body">
                  <div class="mockup-ticket">
                    <div>
                      <div class="mockup-title">Cannot access payroll</div>
                      <div class="meta-pill">AI 92% • keyword: payroll</div>
                    </div>
                    <div class="mockup-badge priority high">High</div>
                  </div>
                  <div class="mockup-ticket">
                    <div>
                      <div class="mockup-title">VPN not connecting</div>
                      <div class="meta-pill">AI 71% • keyword: vpn</div>
                    </div>
                    <div class="mockup-badge priority medium">Medium</div>
                  </div>
                  <div class="mockup-ticket">
                    <div>
                      <div class="mockup-title">Need a new monitor</div>
                      <div class="meta-pill">AI 40% • default</div>
                    </div>
                    <div class="mockup-badge priority low">Low</div>
                  </div>
                </div>
              </div>
            </div>
          </header>
          
          <section class="features-grid">
            <div class="feature-card glass">
              <div class="icon">🤖</div>
              <h3>AI Triage</h3>
              <p>Automatic priority scoring from language and urgency signals so agents never miss critical work.</p>
            </div>
            <div class="feature-card glass">
              <div class="icon">🧭</div>
              <h3>Ownership & Routing</h3>
              <p>One-click assignment, clear SLAs, and a shared queue that keeps every ticket moving.</p>
            </div>
            <div class="feature-card glass">
              <div class="icon">🔒</div>
              <h3>Domain Security</h3>
              <p>Enforce company-only signups and invite gates so your service desk stays internal.</p>
            </div>
            <div class="feature-card glass">
              <div class="icon">📊</div>
              <h3>Actionable Reports</h3>
              <p>Track volume, SLA risk, and resolution trends with simple, readable analytics.</p>
            </div>
          </section>
          <footer class="app-footer">
            <div class="footer-inner">
              <span>Built by watashiii5 • IT Ticketing Desk</span>
              <div>
                <a class="footer-link" href="https://github.com/watashiii5" target="_blank" rel="noreferrer">github.com/watashiii5</a>
                <span> • </span>
                <a class="footer-link" href="https://watashiii5.github.io/portfolio/" target="_blank" rel="noreferrer">watashiii5.github.io/portfolio</a>
              </div>
            </div>
          </footer>
        </main>
      
    <script>
      (function() {
        const isDark = document.documentElement.classList.contains('dark-mode');
        
        window.addEventListener('DOMContentLoaded', () => {
          const btn = document.createElement('div');
          btn.className = 'floating-theme-toggle';
          btn.innerHTML = isDark ? '☀️' : '🌙';
          document.body.appendChild(btn);
          
          btn.addEventListener('click', () => {
            const isDarkNow = document.documentElement.classList.toggle('dark-mode');
            localStorage.setItem('theme', isDarkNow ? 'dark' : 'light');
            btn.innerHTML = isDarkNow ? '☀️' : '🌙';
          });
        });
      })();
    </script>
  
    <script>
      document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', (e) => {
          const btn = form.querySelector('button[type="submit"]');
          if (btn) {
            setTimeout(() => {
              btn.disabled = true;
              btn.innerHTML = '<span class="spinner"></span> Processing...';
            }, 10);
          }
        });
      });
    </script>

      </body>
    </html>
  `;
}

function formatStatus(value) {
  if (value === "in_progress") return "In progress";
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function formatBytes(bytes) {
  if (!bytes && bytes !== 0) return "";
  const units = ["B", "KB", "MB", "GB"];
  let size = bytes;
  let index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  return `${size.toFixed(size >= 10 || index === 0 ? 0 : 1)} ${units[index]}`;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
