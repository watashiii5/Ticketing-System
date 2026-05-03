const express = require("express");
const path = require("path");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const crypto = require("crypto");
const db = require("./db");
const { sendTicketNotification } = require("./notifications");

const app = express();
const port = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
    },
  })
);
app.use("/static", express.static(path.join(__dirname, "..", "public")));
app.use("/uploads", express.static(path.join(__dirname, "..", "uploads")));

const upload = multer({
  storage: multer.diskStorage({
    destination: path.join(__dirname, "..", "uploads"),
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname);
      const name = `${crypto.randomBytes(12).toString("hex")}${ext}`;
      cb(null, name);
    },
  }),
  limits: { fileSize: 8 * 1024 * 1024 },
});

app.use((req, res, next) => {
  if (!req.session.userId) {
    req.user = null;
    return next();
  }

  const user = db
    .prepare("SELECT id, name, role, company_id FROM users WHERE id = ?")
    .get(req.session.userId);
  req.user = user || null;
  if (req.user && req.user.company_id) {
    req.company = db
      .prepare("SELECT id, name, slug, brand_color, logo_url, invite_required, allowed_domains, status FROM companies WHERE id = ?")
      .get(req.user.company_id);
  } else {
    req.company = null;
  }
  next();
});

app.get("/login", (req, res) => {
  if (req.user) {
    return res.redirect("/");
  }

  res.send(renderLogin());
});

app.get("/forgot", (req, res) => {
  if (req.user) {
    return res.redirect("/");
  }

  res.send(renderForgot());
});

app.post("/forgot", (req, res) => {
  const email = (req.body.email || "").trim().toLowerCase();
  if (!email) {
    return res.status(400).send(renderForgot("Email is required."));
  }

  const record = db
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
    const tokenHash = bcrypt.hashSync(rawToken, 10);
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();

    db.prepare(
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

app.get("/reset/:token", (req, res) => {
  if (req.user) {
    return res.redirect("/");
  }

  res.send(renderReset(req.params.token));
});

app.post("/reset/:token", (req, res) => {
  const token = req.params.token;
  const password = req.body.password || "";
  if (!password) {
    return res.status(400).send(renderReset(token, "Password required."));
  }

  const tokens = db
    .prepare(
      "SELECT id, user_id, token_hash, expires_at, used_at FROM reset_tokens ORDER BY id DESC LIMIT 25"
    )
    .all();

  const now = Date.now();
  const matched = tokens.find((row) => {
    if (row.used_at) return false;
    if (new Date(row.expires_at).getTime() < now) return false;
    return bcrypt.compareSync(token, row.token_hash);
  });

  if (!matched) {
    return res.status(400).send(renderReset(token, "Invalid or expired token."));
  }

  const passwordHash = bcrypt.hashSync(password, 10);
  db.prepare("UPDATE credentials SET password_hash = ? WHERE user_id = ?").run(
    passwordHash,
    matched.user_id
  );
  db.prepare("UPDATE reset_tokens SET used_at = ? WHERE id = ?").run(
    new Date().toISOString(),
    matched.id
  );

  const userCompany = db
    .prepare("SELECT company_id FROM users WHERE id = ?")
    .get(matched.user_id);
  logAudit(
    null,
    userCompany ? userCompany.company_id : null,
    "user.reset_password_link",
    "user",
    matched.user_id,
    "password reset"
  );
  res.send(renderLogin("Password reset. You can sign in now."));
});

app.get("/admin/users", requireAuth, requireAgent, requireCompanyActive, (req, res) => {
  const users = db
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
  const invites = db
    .prepare(
      "SELECT id, email, role, expires_at, used_at FROM invites WHERE company_id = ? ORDER BY id DESC"
    )
    .all(req.user.company_id);
  res.send(renderUserAdmin(users, invites, req.user));
});

app.post("/admin/users", requireAuth, requireAgent, requireCompanyActive, (req, res) => {
  const name = (req.body.name || "").trim();
  const email = (req.body.email || "").trim().toLowerCase();
  const role = (req.body.role || "requester").trim();
  const password = req.body.password || "";

  if (!name || !email || !password) {
    return res.status(400).send("Name, email, and password are required.");
  }

  const passwordHash = bcrypt.hashSync(password, 10);
  const insertUser = db.prepare(
    "INSERT INTO users (name, role, company_id) VALUES (?, ?, ?)"
  );
  const insertCred = db.prepare(
    "INSERT INTO credentials (user_id, email, password_hash) VALUES (?, ?, ?)"
  );
  const transaction = db.transaction(() => {
    const info = insertUser.run(name, role, req.user.company_id);
    insertCred.run(info.lastInsertRowid, email, passwordHash);
  });

  transaction();
  logAudit(
    req.user.id,
    req.user.company_id,
    "user.create",
    "user",
    null,
    JSON.stringify({ name, email, role })
  );
  res.redirect("/admin/users");
});

app.post("/admin/users/:id/reset", requireAuth, requireAgent, requireCompanyActive, (req, res) => {
  const id = Number(req.params.id);
  const newPassword = req.body.password || "";
  if (!newPassword) {
    return res.status(400).send("Password required.");
  }

  const passwordHash = bcrypt.hashSync(newPassword, 10);
  const user = db.prepare("SELECT company_id FROM users WHERE id = ?").get(id);
  if (!user || user.company_id !== req.user.company_id) {
    return res.status(403).send("Not allowed.");
  }

  db.prepare("UPDATE credentials SET password_hash = ? WHERE user_id = ?").run(passwordHash, id);
  logAudit(req.user.id, req.user.company_id, "user.reset_password", "user", id, "reset password");
  res.redirect("/admin/users");
});

app.post("/admin/invites", requireAuth, requireAgent, requireCompanyActive, (req, res) => {
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
  const tokenHash = bcrypt.hashSync(rawToken, 10);
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

  db.prepare(
    "INSERT INTO invites (company_id, email, role, token_hash, expires_at) VALUES (?, ?, ?, ?, ?)"
  ).run(req.user.company_id, email, role, tokenHash, expiresAt);

  const inviteLink = `${req.protocol}://${req.get("host")}/invite/${rawToken}`;
  sendTicketNotification({
    to: email,
    subject: `You're invited to ${req.company ? req.company.name : "Service Desk"}`,
    text: `Use this invite link to join: ${inviteLink}`,
  });

  logAudit(req.user.id, req.user.company_id, "invite.create", "company", req.user.company_id, email);
  res.redirect("/admin/users");
});

app.get("/admin/company", requireAuth, requireAgent, requireCompanyActive, (req, res) => {
  const company = db
    .prepare(
      "SELECT id, name, slug, brand_color, logo_url, invite_required, allowed_domains, status, plan FROM companies WHERE id = ?"
    )
    .get(req.user.company_id);
  res.send(renderCompanySettings(company, req.user));
});

app.post("/admin/company", requireAuth, requireAgent, requireCompanyActive, (req, res) => {
  const slug = (req.body.slug || "").trim().toLowerCase();
  const brandColor = (req.body.brand_color || "").trim();
  const logoUrl = (req.body.logo_url || "").trim();
  const allowedDomains = (req.body.allowed_domains || "").trim();
  const inviteRequired = req.body.invite_required ? 1 : 0;

  db.prepare(
    "UPDATE companies SET slug = ?, brand_color = ?, logo_url = ?, invite_required = ?, allowed_domains = ? WHERE id = ?"
  ).run(
    slug || slugify(req.company.name),
    brandColor || null,
    logoUrl || null,
    inviteRequired,
    allowedDomains || null,
    req.user.company_id
  );

  logAudit(req.user.id, req.user.company_id, "company.update", "company", req.user.company_id, "settings");
  res.redirect("/admin/company");
});

app.post("/login", (req, res) => {
  const email = (req.body.email || "").trim().toLowerCase();
  const password = req.body.password || "";

  if (!email || !password) {
    return res.status(400).send(renderLogin("Email and password are required."));
  }

  const record = db
    .prepare(
      `
        SELECT credentials.user_id, credentials.password_hash, users.name, users.role, users.company_id
        FROM credentials
        JOIN users ON users.id = credentials.user_id
        WHERE credentials.email = ?
      `
    )
    .get(email);

  if (!record || !bcrypt.compareSync(password, record.password_hash)) {
    return res.status(401).send(renderLogin("Invalid credentials."));
  }

  if (record.company_id) {
    const company = db
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
  res.redirect("/");
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

app.get("/", requireAuth, requireCompanyActive, (req, res) => {
  const scopeClause = req.user.role === "agent" ? "" : "AND tickets.user_id = ?";
  const scopeParams = req.user.role === "agent" ? [] : [req.user.id];
  const tickets = db
    .prepare(
      `
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
          requester.name as requester_name,
          requester.role as requester_role,
          assignee.name as assignee_name
        FROM tickets
        LEFT JOIN users requester ON requester.id = tickets.user_id
        LEFT JOIN users assignee ON assignee.id = tickets.assignee_id
        WHERE tickets.company_id = ? ${scopeClause}
        ORDER BY tickets.id DESC
      `
    )
    .all(req.user.company_id, ...scopeParams);

  const users = db.prepare("SELECT id, name, role FROM users ORDER BY name").all();
  const ticketIds = tickets.map((ticket) => ticket.id);
  const commentsByTicketId = ticketIds.length
    ? getCommentsByTicketId(ticketIds)
    : {};
  const attachmentsByTicketId = ticketIds.length
    ? getAttachmentsByTicketId(ticketIds)
    : {};

  res.send(
    renderHome(
      tickets,
      users,
      commentsByTicketId,
      attachmentsByTicketId,
      null,
      req.user,
      req.company
    )
  );
});

app.post("/tickets", requireAuth, requireCompanyActive, (req, res) => {
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

  const now = new Date().toISOString();
  const slaDueAt = rawSla
    ? new Date(rawSla).toISOString()
    : computeSlaDueAt(priority);
  const result = db
    .prepare(
      "INSERT INTO tickets (title, description, company_id, user_id, status, priority, priority_confidence, priority_reason, sla_due_at, created_at) VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?, ?)"
    )
    .run(
      title,
      description,
      req.user.company_id,
      requesterId,
      priority,
      priorityResult.confidence,
      priorityResult.reason,
      slaDueAt,
      now
    );

  notifyTicketCreated(result.lastInsertRowid, title, description, priority, req.user);
  logAudit(
    req.user.id,
    req.user.company_id,
    "ticket.create",
    "ticket",
    result.lastInsertRowid,
    title
  );

  res.redirect("/");
});

app.post("/tickets/:id/comment", requireAuth, requireCompanyActive, (req, res) => {
  const id = Number(req.params.id);
  const body = (req.body.body || "").trim();

  if (!body) {
    return res.status(400).send("Comment is required.");
  }

  const now = new Date().toISOString();
  db.prepare(
    "INSERT INTO comments (ticket_id, user_id, body, created_at) VALUES (?, ?, ?, ?)"
  ).run(id, req.user.id, body, now);

  notifyTicketCommented(id, body, req.user);
  logAudit(
    req.user.id,
    req.user.company_id,
    "ticket.comment",
    "ticket",
    id,
    body.slice(0, 120)
  );
  res.redirect("/");
});

app.post(
  "/tickets/:id/attachments",
  requireAuth,
  requireCompanyActive,
  upload.single("attachment"),
  (req, res) => {
    const id = Number(req.params.id);
    if (!req.file) {
      return res.status(400).send("Attachment required.");
    }

    const now = new Date().toISOString();
    db.prepare(
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

    logAudit(
      req.user.id,
      req.user.company_id,
      "ticket.attachment",
      "ticket",
      id,
      req.file.originalname
    );
    res.redirect("/");
  }
);

app.get("/search", requireAuth, requireCompanyActive, (req, res) => {
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

  if (req.user.role !== "agent") {
    filters.push("tickets.user_id = ?");
    params.push(req.user.id);
  }

  const whereClause = filters.length ? `WHERE ${filters.join(" AND ")}` : "";

  const tickets = db
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
        ${filters.length ? "AND" : "WHERE"} tickets.company_id = ?
        ${whereClause}
        ORDER BY tickets.id DESC
      `
    )
    .all(...params, req.user.company_id);

  const users = db.prepare("SELECT id, name, role FROM users ORDER BY name").all();
  const ticketIds = tickets.map((ticket) => ticket.id);
  const commentsByTicketId = ticketIds.length
    ? getCommentsByTicketId(ticketIds)
    : {};
  const attachmentsByTicketId = ticketIds.length
    ? getAttachmentsByTicketId(ticketIds)
    : {};

  res.send(
    renderHome(
      tickets,
      users,
      commentsByTicketId,
      attachmentsByTicketId,
      { status, priority, term },
      req.user,
      req.company
    )
  );
});

app.get("/reports", requireAuth, requireAgent, requireCompanyActive, (req, res) => {
  const total = db
    .prepare("SELECT COUNT(*) as count FROM tickets WHERE company_id = ?")
    .get(req.user.company_id).count;
  const open = db
    .prepare("SELECT COUNT(*) as count FROM tickets WHERE status = 'open' AND company_id = ?")
    .get(req.user.company_id).count;
  const inProgress = db
    .prepare(
      "SELECT COUNT(*) as count FROM tickets WHERE status = 'in_progress' AND company_id = ?"
    )
    .get(req.user.company_id).count;
  const resolved = db
    .prepare("SELECT COUNT(*) as count FROM tickets WHERE status = 'resolved' AND company_id = ?")
    .get(req.user.company_id).count;
  const overdue = db
    .prepare(
      "SELECT COUNT(*) as count FROM tickets WHERE sla_due_at IS NOT NULL AND sla_due_at < ? AND status != 'resolved' AND company_id = ?"
    )
    .get(new Date().toISOString(), req.user.company_id).count;

  const topPriorities = db
    .prepare(
      "SELECT priority, COUNT(*) as count FROM tickets WHERE company_id = ? GROUP BY priority ORDER BY count DESC"
    )
    .all(req.user.company_id);

  res.send(
    renderReports(
      { total, open, inProgress, resolved, overdue, topPriorities },
      req.user
    )
  );
});

app.post("/tickets/:id/status", requireAuth, requireAgent, requireCompanyActive, (req, res) => {
  const id = Number(req.params.id);
  const status = (req.body.status || "open").trim();
  const allowed = new Set(["open", "in_progress", "resolved"]);

  if (!allowed.has(status)) {
    return res.status(400).send("Invalid status.");
  }

  db.prepare("UPDATE tickets SET status = ? WHERE id = ?").run(status, id);
  notifyTicketStatus(id, status, req.user);
  logAudit(req.user.id, req.user.company_id, "ticket.status", "ticket", id, status);
  res.redirect("/");
});

app.post("/tickets/:id/priority", requireAuth, requireAgent, requireCompanyActive, (req, res) => {
  const id = Number(req.params.id);
  const priority = (req.body.priority || "medium").trim();
  const allowed = new Set(["low", "medium", "high"]);
  const reason = (req.body.reason || "").trim();

  if (!allowed.has(priority)) {
    return res.status(400).send("Invalid priority.");
  }

  const slaDueAt = computeSlaDueAt(priority);
  db.prepare(
    "UPDATE tickets SET priority = ?, priority_confidence = ?, priority_reason = ?, sla_due_at = ? WHERE id = ?"
  ).run(priority, 1, reason || "agent override", slaDueAt, id);
  notifyTicketPriority(id, priority, req.user);
  logAudit(
    req.user.id,
    req.user.company_id,
    "ticket.priority",
    "ticket",
    id,
    reason ? `${priority} | ${reason}` : priority
  );
  res.redirect("/");
});

app.post("/tickets/:id/assign", requireAuth, requireAgent, requireCompanyActive, (req, res) => {
  const id = Number(req.params.id);
  const assigneeId = Number(req.body.assignee_id || 0) || null;

  db.prepare("UPDATE tickets SET assignee_id = ? WHERE id = ?").run(assigneeId, id);
  notifyTicketAssigned(id, assigneeId, req.user);
  logAudit(
    req.user.id,
    req.user.company_id,
    "ticket.assign",
    "ticket",
    id,
    String(assigneeId || "none")
  );
  res.redirect("/");
});

app.post("/tickets/:id/sla", requireAuth, requireAgent, requireCompanyActive, (req, res) => {
  const id = Number(req.params.id);
  const raw = (req.body.sla_due_at || "").trim();
  if (!raw) {
    return res.status(400).send("SLA due date required.");
  }

  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) {
    return res.status(400).send("Invalid SLA date.");
  }

  db.prepare("UPDATE tickets SET sla_due_at = ? WHERE id = ?").run(
    parsed.toISOString(),
    id
  );
  notifyTicketSla(id, parsed.toISOString(), req.user);
  logAudit(
    req.user.id,
    req.user.company_id,
    "ticket.sla",
    "ticket",
    id,
    parsed.toISOString()
  );
  res.redirect("/");
});

app.post("/tickets/:id/delete", requireAuth, requireAgent, requireCompanyActive, (req, res) => {
  const id = Number(req.params.id);
  db.prepare("DELETE FROM tickets WHERE id = ?").run(id);
  logAudit(req.user.id, req.user.company_id, "ticket.delete", "ticket", id, "deleted");
  res.redirect("/");
});

app.get("/platform", requireAuth, requireSuperAdmin, (req, res) => {
  const companies = db
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
  const payments = db
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

app.post("/platform/companies/:id/approve", requireAuth, requireSuperAdmin, (req, res) => {
  const id = Number(req.params.id);
  db.prepare("UPDATE companies SET status = 'active' WHERE id = ?").run(id);
  logAudit(req.user.id, null, "company.approve", "company", id, "approved");
  res.redirect("/platform");
});

app.post("/platform/companies/:id/suspend", requireAuth, requireSuperAdmin, (req, res) => {
  const id = Number(req.params.id);
  db.prepare("UPDATE companies SET status = 'suspended' WHERE id = ?").run(id);
  logAudit(req.user.id, null, "company.suspend", "company", id, "suspended");
  res.redirect("/platform");
});

app.post("/billing/verify", requireAuth, requireSuperAdmin, (req, res) => {
  const id = Number(req.body.request_id || 0);
  const request = db
    .prepare("SELECT company_id FROM payment_requests WHERE id = ?")
    .get(id);

  if (!request) {
    return res.status(404).send("Payment request not found.");
  }

  db.prepare("UPDATE payment_requests SET status = 'paid', paid_at = ? WHERE id = ?").run(
    new Date().toISOString(),
    id
  );
  db.prepare("UPDATE companies SET status = 'active' WHERE id = ?").run(request.company_id);
  logAudit(req.user.id, null, "billing.verified", "company", request.company_id, "paid");
  res.redirect("/platform");
});

app.get("/signup", (req, res) => {
  if (req.user) {
    return res.redirect("/");
  }
  res.send(renderSignup());
});

app.get("/c/:slug", (req, res) => {
  const slug = (req.params.slug || "").trim().toLowerCase();
  const company = db
    .prepare(
      "SELECT id, name, slug, brand_color, logo_url, invite_required, allowed_domains, status FROM companies WHERE slug = ?"
    )
    .get(slug);
  if (!company) {
    return res.status(404).send("Company not found.");
  }

  res.send(renderCompanyLanding(company));
});

app.post("/signup", (req, res) => {
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

  if (domains) {
    const allowed = domains
      .split(",")
      .map((item) => item.trim().toLowerCase())
      .filter(Boolean);
    const domain = email.split("@")[1] || "";
    if (allowed.length && !allowed.includes(domain)) {
      return res
        .status(400)
        .send(renderSignup("Your email domain is not in the allowed list."));
    }
  }

  const now = new Date().toISOString();
  const trialEndsAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  const passwordHash = bcrypt.hashSync(password, 10);
  const createCompany = db.prepare(
    "INSERT INTO companies (name, slug, invite_required, allowed_domains, status, plan, trial_ends_at, created_at) VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)"
  );
  const createUser = db.prepare(
    "INSERT INTO users (name, role, company_id) VALUES (?, 'agent', ?)"
  );
  const createCred = db.prepare(
    "INSERT INTO credentials (user_id, email, password_hash) VALUES (?, ?, ?)"
  );

  const transaction = db.transaction(() => {
    const companyId = createCompany.run(
      companyName,
      slug || slugify(companyName),
      inviteRequired,
      domains,
      plan,
      trialEndsAt,
      now
    ).lastInsertRowid;
    const userId = createUser.run(name, companyId).lastInsertRowid;
    createCred.run(userId, email, passwordHash);
    logAudit(userId, companyId, "company.signup", "company", companyId, plan);
  });

  transaction();
  res.send(renderSignup("Signup received. You have a 30-day trial. Submit payment to stay active."));
});

app.get("/billing", requireAuth, (req, res) => {
  if (req.user.role === "super_admin") {
    return res.redirect("/platform");
  }

  const company = db
    .prepare("SELECT id, name, status, plan FROM companies WHERE id = ?")
    .get(req.user.company_id);
  const payments = db
    .prepare(
      "SELECT id, method, reference, amount, status, created_at FROM payment_requests WHERE company_id = ? ORDER BY id DESC"
    )
    .all(req.user.company_id);

  res.send(renderBilling(company, payments, req.user));
});


app.post("/billing/request", requireAuth, (req, res) => {
  const method = (req.body.method || "manual").trim();
  const reference = (req.body.reference || "").trim();
  const amount = (req.body.amount || "").trim();
  const company = db
    .prepare("SELECT id, status FROM companies WHERE id = ?")
    .get(req.user.company_id);

  if (!company) {
    return res.status(400).send("Company not found.");
  }

  db.prepare(
    "INSERT INTO payment_requests (company_id, owner_id, method, reference, amount, status, created_at) VALUES (?, ?, ?, ?, ?, 'pending', ?)"
  ).run(company.id, req.user.id, method, reference, amount, new Date().toISOString());

  logAudit(req.user.id, req.user.company_id, "billing.request", "company", company.id, method);
  res.redirect("/billing");
});

app.get("/invite/:token", (req, res) => {
  if (req.user) {
    return res.redirect("/");
  }

  res.send(renderInviteAccept(req.params.token));
});

app.post("/invite/:token", (req, res) => {
  const token = req.params.token;
  const name = (req.body.name || "").trim();
  const password = req.body.password || "";
  if (!name || !password) {
    return res.status(400).send(renderInviteAccept(token, "Name and password required."));
  }

  const invites = db
    .prepare(
      "SELECT id, company_id, email, role, token_hash, expires_at, used_at FROM invites ORDER BY id DESC LIMIT 50"
    )
    .all();

  const now = Date.now();
  const matched = invites.find((row) => {
    if (row.used_at) return false;
    if (new Date(row.expires_at).getTime() < now) return false;
    return bcrypt.compareSync(token, row.token_hash);
  });

  if (!matched) {
    return res.status(400).send(renderInviteAccept(token, "Invalid or expired invite."));
  }

  const passwordHash = bcrypt.hashSync(password, 10);
  const createUser = db.prepare(
    "INSERT INTO users (name, role, company_id) VALUES (?, ?, ?)"
  );
  const createCred = db.prepare(
    "INSERT INTO credentials (user_id, email, password_hash) VALUES (?, ?, ?)"
  );

  const transaction = db.transaction(() => {
    const userId = createUser.run(name, matched.role, matched.company_id).lastInsertRowid;
    createCred.run(userId, matched.email, passwordHash);
    db.prepare("UPDATE invites SET used_at = ? WHERE id = ?").run(
      new Date().toISOString(),
      matched.id
    );
  });

  transaction();
  res.send(renderLogin("Invite accepted. You can sign in now."));
});

app.listen(port, () => {
  console.log(`Ticketing app running on http://localhost:${port}`);
});

function renderHome(
  tickets,
  users,
  commentsByTicketId,
  attachmentsByTicketId,
  filters = null,
  currentUser,
  currentCompany
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

  const rows = tickets
    .map(
      (ticket) => `
        <li class="ticket">
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
              <span class="badge status ${ticket.status}">${formatStatus(ticket.status)}</span>
              <span class="badge priority ${ticket.priority}">${ticket.priority}</span>
              ${renderPriorityMeta(ticket.priority_confidence, ticket.priority_reason)}
              ${renderSlaBadge(ticket.sla_due_at)}
              <span class="timestamp">${new Date(ticket.created_at).toLocaleString()}</span>
            </div>
          </div>
          <div class="ticket-actions">
            ${
              currentUser.role === "agent"
                ? `
                  <form action="/tickets/${ticket.id}/status" method="post">
                    <select name="status" onchange="this.form.submit()">
                      ${renderOption("open", ticket.status)}
                      ${renderOption("in_progress", ticket.status, "In progress")}
                      ${renderOption("resolved", ticket.status)}
                    </select>
                  </form>
                  <form action="/tickets/${ticket.id}/priority" method="post" class="priority-form">
                    <select name="priority" onchange="this.form.submit()">
                      ${renderOption("low", ticket.priority)}
                      ${renderOption("medium", ticket.priority)}
                      ${renderOption("high", ticket.priority)}
                    </select>
                    <input name="reason" placeholder="Reason (optional)" />
                    <button type="submit">Update</button>
                  </form>
                  <form action="/tickets/${ticket.id}/assign" method="post">
                    <select name="assignee_id" onchange="this.form.submit()">
                      <option value="">Unassigned</option>
                      ${renderOptionList(agentOptions, ticket.assignee_id)}
                    </select>
                  </form>
                  <form action="/tickets/${ticket.id}/delete" method="post">
                    <button type="submit" class="danger">Delete</button>
                  </form>
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
              ${renderAttachments(attachmentsByTicketId[ticket.id])}
            </ul>
            <form action="/tickets/${ticket.id}/attachments" method="post" enctype="multipart/form-data" class="attachment-form">
              <input type="file" name="attachment" required />
              <button type="submit">Upload</button>
            </form>
          </div>
          ${
            currentUser.role === "agent"
              ? `
                <form action="/tickets/${ticket.id}/sla" method="post" class="sla-form">
                  <label for="sla-${ticket.id}">Adjust SLA</label>
                  <input id="sla-${ticket.id}" type="datetime-local" name="sla_due_at" />
                  <button type="submit">Update SLA</button>
                </form>
              `
              : ""
          }
        </li>
      `
    )
    .join("");

  return `
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>IT Ticketing Desk</title>
        <link rel="stylesheet" href="/static/styles.css" />
      </head>
      <body>
        <main class="shell" style="--brand:${
          currentCompany?.brand_color ? escapeHtml(currentCompany.brand_color) : "#d26a2b"
        }">
          <header class="topbar">
            <div>
              <h2>${escapeHtml(currentCompany?.name || "Service Desk")}</h2>
              <p>Signed in as ${escapeHtml(currentUser.name)} (${currentUser.role})</p>
            </div>
            <div class="top-actions">
              ${
                currentUser.role === "agent"
                  ? `
                    <a class="ghost" href="/reports">Reports</a>
                    <a class="ghost" href="/admin/users">Users</a>
                    <a class="ghost" href="/admin/company">Company</a>
                  `
                  : ""
              }
              <form action="/logout" method="post">
                <button type="submit" class="ghost">Log out</button>
              </form>
            </div>
          </header>
          ${trialBanner}
          <section class="hero">
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
            <form class="filters ${currentUser.role === "agent" ? "" : "single"}" action="/search" method="get">
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
            <form class="ticket-form" action="/tickets" method="post">
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
              ${
                currentUser.role === "agent"
                  ? `
                    <div>
                      <label for="sla">SLA due</label>
                      <input id="sla" type="datetime-local" name="sla_due_at" />
                    </div>
                  `
                  : ""
              }
              <div class="full actions">
                <button type="submit">Create ticket</button>
              </div>
            </form>
          </section>

          <section class="panel">
            <h2>Queue</h2>
            <p class="filter-note">Showing ${tickets.length} ticket(s) • <a href="/search?${filterQuery}">Permalink</a> • <a href="/">Clear filters</a></p>
            <ul class="tickets">
              ${rows || "<li class=\"empty\">No tickets yet. Add the first request above.</li>"}
            </ul>
          </section>
        </main>
      </body>
    </html>
  `;
}

function getCommentsByTicketId(ticketIds) {
  const placeholders = ticketIds.map(() => "?").join(",");
  const rows = db
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

function getAttachmentsByTicketId(ticketIds) {
  const placeholders = ticketIds.map(() => "?").join(",");
  const rows = db
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
    return res.redirect("/login");
  }
  next();
}

function requireAgent(req, res, next) {
  if (!req.user || req.user.role !== "agent") {
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

function requireCompanyActive(req, res, next) {
  const company = db
    .prepare("SELECT status, trial_ends_at FROM companies WHERE id = ?")
    .get(req.user.company_id);
  if (!company) {
    return res.status(402).send(renderBillingGate(req.user));
  }

  if (company.status === "active") {
    return next();
  }

  const trialEndsAt = company.trial_ends_at ? new Date(company.trial_ends_at) : null;
  if (trialEndsAt && Date.now() <= trialEndsAt.getTime()) {
    return next();
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

function logAudit(actorId, companyId, action, entityType, entityId, details) {
  db.prepare(
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
  if (currentCompany.status === "active") return "";

  if (currentCompany.trial_ends_at) {
    const daysLeft = Math.ceil(
      (new Date(currentCompany.trial_ends_at).getTime() - Date.now()) /
        (1000 * 60 * 60 * 24)
    );
    if (daysLeft > 0) {
      return `
        <div class="trial-banner">
          <strong>Free trial:</strong> ${daysLeft} day(s) left. Submit payment to keep access.
          <a href="/billing">Go to billing</a>
        </div>
      `;
    }
  }

  return `
    <div class="trial-banner overdue">
      <strong>Trial ended:</strong> Please submit payment to continue using the service.
      <a href="/billing">Go to billing</a>
    </div>
  `;
}

function renderOptionList(optionsHtml, selectedId) {
  if (!selectedId) return optionsHtml;
  return optionsHtml.replace(
    new RegExp(`value=\"${selectedId}\"`, "g"),
    `value=\"${selectedId}\" selected`
  );
}

function renderLogin(error = "") {
  return `
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Login • Service Desk</title>
        <link rel="stylesheet" href="/static/styles.css" />
      </head>
      <body>
        <main class="shell login-shell">
          <section class="panel login-panel">
            <h1>Sign in</h1>
            <p class="subtitle">Use the demo accounts to access the service desk.</p>
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
            <div class="login-hint">
              <p>Demo password for all users: <strong>password123</strong></p>
              <p>Example: <strong>avery.kim@acme.test</strong> (requester) or <strong>morgan.diaz@acme.test</strong> (agent)</p>
            </div>
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
      </body>
    </html>
  `;
}

function renderSignup(message = "") {
  return `
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Company signup</title>
        <link rel="stylesheet" href="/static/styles.css" />
      </head>
      <body>
        <main class="shell login-shell">
          <section class="panel login-panel">
            <h1>Create company account</h1>
            <p class="subtitle">Start with a 1-click setup. Payment is required before access.</p>
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
              <label for="plan">Plan</label>
              <select id="plan" name="plan">
                <option value="starter">Starter</option>
                <option value="growth">Growth</option>
                <option value="enterprise">Enterprise</option>
              </select>
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
      </body>
    </html>
  `;
}

function renderBillingGate(currentUser) {
  return `
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Billing required</title>
        <link rel="stylesheet" href="/static/styles.css" />
      </head>
      <body>
        <main class="shell login-shell">
          <section class="panel login-panel">
            <h1>Payment required</h1>
            <p class="subtitle">Your company account needs activation.</p>
            <p class="notice">Submit payment to unlock access or continue your free trial.</p>
            <a class="ghost" href="/billing">Go to billing</a>
            <form action="/logout" method="post" class="helper">
              <button type="submit" class="ghost">Log out</button>
            </form>
          </section>
        </main>
      </body>
    </html>
  `;
}

function renderCompanySettings(company, currentUser) {
  return `
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Company settings</title>
        <link rel="stylesheet" href="/static/styles.css" />
      </head>
      <body>
        <main class="shell">
          <header class="topbar">
            <div>
              <h2>Company settings</h2>
              <p>${escapeHtml(company.name)} • Plan: ${escapeHtml(company.plan)}</p>
            </div>
            <div class="top-actions">
              <a class="ghost" href="/admin/users">Back to users</a>
              <form action="/logout" method="post">
                <button type="submit" class="ghost">Log out</button>
              </form>
            </div>
          </header>

          <section class="panel">
            <form class="ticket-form" action="/admin/company" method="post">
              <div>
                <label for="slug">Company URL slug</label>
                <input id="slug" name="slug" value="${escapeHtml(company.slug || "")}" />
              </div>
              <div>
                <label for="brand_color">Brand color</label>
                <input id="brand_color" name="brand_color" placeholder="#d26a2b" value="${escapeHtml(
                  company.brand_color || ""
                )}" />
              </div>
              <div>
                <label for="logo_url">Logo URL</label>
                <input id="logo_url" name="logo_url" placeholder="https://..." value="${escapeHtml(
                  company.logo_url || ""
                )}" />
              </div>
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
      </body>
    </html>
  `;
}

function renderBilling(company, payments, currentUser) {
  const rows = payments
    .map(
      (payment) => `
        <tr>
          <td>${escapeHtml(payment.method)}</td>
          <td>${escapeHtml(payment.reference || "")}</td>
          <td>${escapeHtml(payment.amount || "")}</td>
          <td>${escapeHtml(payment.status)}</td>
          <td>${new Date(payment.created_at).toLocaleString()}</td>
        </tr>
      `
    )
    .join("");

  return `
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Billing</title>
        <link rel="stylesheet" href="/static/styles.css" />
      </head>
      <body>
        <main class="shell">
          <header class="topbar">
            <div>
              <h2>Billing</h2>
              <p>${escapeHtml(company.name)} • Status: ${escapeHtml(company.status)}</p>
            </div>
            <div class="top-actions">
              <a class="ghost" href="/">Back to desk</a>
              <form action="/logout" method="post">
                <button type="submit" class="ghost">Log out</button>
              </form>
            </div>
          </header>

          <section class="panel">
            <h3>Submit payment</h3>
            <p class="subtitle">Choose a method. We will activate your company after verification.</p>
            <div class="notice">
              <p><strong>Stripe / PayPal / GCash setup pending.</strong> You can submit your transaction reference now.</p>
              <p>Once we add live keys, payments can be auto-verified.</p>
            </div>
            <form class="ticket-form" action="/billing/request" method="post">
              <div>
                <label for="method">Payment method</label>
                <select id="method" name="method">
                  <option value="stripe">Stripe (card)</option>
                  <option value="paypal">PayPal</option>
                  <option value="gcash">GCash</option>
                  <option value="bank">Bank transfer</option>
                </select>
              </div>
              <div>
                <label for="amount">Amount</label>
                <input id="amount" name="amount" placeholder="e.g. 2999 PHP" />
              </div>
              <div>
                <label for="reference">Reference / Transaction ID</label>
                <input id="reference" name="reference" placeholder="Paste payment reference" />
              </div>
              <div class="full actions">
                <button type="submit">Submit payment</button>
              </div>
            </form>
          </section>

          <section class="panel">
            <h3>Payment history</h3>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Method</th>
                    <th>Reference</th>
                    <th>Amount</th>
                    <th>Status</th>
                    <th>Submitted</th>
                  </tr>
                </thead>
                <tbody>
                  ${rows || "<tr><td colspan=\"5\">No payments yet.</td></tr>"}
                </tbody>
              </table>
            </div>
          </section>
        </main>
      </body>
    </html>
  `;
}

function renderCompanyLanding(company) {
  return `
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>${escapeHtml(company.name)} Service Desk</title>
        <link rel="stylesheet" href="/static/styles.css" />
      </head>
      <body>
        <main class="shell login-shell">
          <section class="panel landing">
            <div class="landing-header">
              <div>
                <p class="eyebrow">${escapeHtml(company.plan)} plan</p>
                <h1>${escapeHtml(company.name)} Service Desk</h1>
                <p class="subtitle">Fast, structured IT support with clear priorities, SLAs, and real-time updates.</p>
              </div>
              ${
                company.logo_url
                  ? `<img class=\"brand-logo\" src=\"${escapeHtml(
                      company.logo_url
                    )}\" alt=\"${escapeHtml(company.name)} logo\" />`
                  : ""
              }
            </div>
            <div class="landing-actions">
              <a class="ghost primary" href="/login">Sign in</a>
              <a class="ghost" href="/signup">Create company</a>
            </div>
            <div class="landing-grid">
              <div>
                <h3>AI‑guided priority</h3>
                <p>Requests are assessed automatically with a confidence tag, then agents can override with reason.</p>
              </div>
              <div>
                <h3>Secure access</h3>
                <p>Invite‑only or domain‑restricted access keeps your queue private and auditable.</p>
              </div>
              <div>
                <h3>Billing control</h3>
                <p>Start a 30‑day trial and unlock production features after payment verification.</p>
              </div>
            </div>
            ${
              company.invite_required
                ? `<p class=\"notice\">Invite-only access is enabled.</p>`
                : `<p class=\"notice\">Ask your admin for an invite or sign up with an approved email domain.</p>`
            }
          </section>
        </main>
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
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Platform Admin</title>
        <link rel="stylesheet" href="/static/styles.css" />
      </head>
      <body>
        <main class="shell">
          <header class="topbar">
            <div>
              <h2>Platform Admin</h2>
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
      </body>
    </html>
  `;
}

function renderForgot(message = "") {
  return `
    <!doctype html>
    <html lang="en">
      <head>
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
      </body>
    </html>
  `;
}

function renderReset(token, error = "") {
  return `
    <!doctype html>
    <html lang="en">
      <head>
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
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>User Admin</title>
        <link rel="stylesheet" href="/static/styles.css" />
      </head>
      <body>
        <main class="shell">
          <header class="topbar">
            <div>
              <h2>User Admin</h2>
              <p>Signed in as ${escapeHtml(currentUser.name)} (${currentUser.role})</p>
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

function renderReports(metrics, currentUser) {
  const rows = metrics.topPriorities
    .map((row) => `<li>${escapeHtml(row.priority)}: ${row.count}</li>`)
    .join("");

  return `
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Reports</title>
        <link rel="stylesheet" href="/static/styles.css" />
      </head>
      <body>
        <main class="shell">
          <header class="topbar">
            <div>
              <h2>Reports</h2>
              <p>Signed in as ${escapeHtml(currentUser.name)} (${currentUser.role})</p>
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
        </main>
      </body>
    </html>
  `;
}

function notifyTicketCreated(id, title, description, priority, actor) {
  sendTicketNotification({
    subject: `New ticket #${id}: ${title}`,
    text: `New ticket created by ${actor.name} (${actor.role})\nPriority: ${priority}\n\n${description}`,
  });
}

function notifyTicketCommented(id, body, actor) {
  sendTicketNotification({
    subject: `Ticket #${id} updated`,
    text: `${actor.name} added a comment:\n${body}`,
  });
}

function notifyTicketStatus(id, status, actor) {
  sendTicketNotification({
    subject: `Ticket #${id} status changed`,
    text: `${actor.name} set status to ${status}.`,
  });
}

function notifyTicketPriority(id, priority, actor) {
  sendTicketNotification({
    subject: `Ticket #${id} priority updated`,
    text: `${actor.name} set priority to ${priority}.`,
  });
}

function notifyTicketAssigned(id, assigneeId, actor) {
  const assignee = assigneeId
    ? db.prepare("SELECT name FROM users WHERE id = ?").get(assigneeId)
    : null;
  sendTicketNotification({
    subject: `Ticket #${id} assigned`,
    text: `${actor.name} assigned ticket to ${assignee ? assignee.name : "Unassigned"}.`,
  });
}

function notifyTicketSla(id, slaDueAt, actor) {
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

function renderAttachments(attachments = []) {
  if (!attachments.length) {
    return "<li class=\"empty\">No files uploaded.</li>";
  }

  return attachments
    .map(
      (attachment) => `
        <li>
          <a href="/uploads/${encodeURIComponent(attachment.stored_name)}" target="_blank" rel="noreferrer">${escapeHtml(
            attachment.original_name
          )}</a>
          <span>${formatBytes(attachment.size_bytes)}</span>
        </li>
      `
    )
    .join("");
}

function renderOption(value, current, label = value) {
  return `<option value="${value}" ${value === current ? "selected" : ""}>${label}</option>`;
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
