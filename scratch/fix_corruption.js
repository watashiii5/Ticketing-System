const fs = require('fs');
const filePath = 'c:\\OpenCode_AI\\ticketing-app\\src\\server.js';
let content = fs.readFileSync(filePath, 'utf8');

const oldBlock = `function requireAgent(req, res, next) {\r
  if (!req.user || (req.user.role !== "agent" && req.user.role !== "super_admin")) {\r
    return res.status(403).send("Agent access required.");\r
  }\r
    .replace(/[^a-z0-9\\s-]/g, "")\r
    .trim()\r
    .replace(/\\s+/g, "-");\r
}`;

const newBlock = `function requireAgent(req, res, next) {\r
  if (!req.user || (req.user.role !== "agent" && req.user.role !== "super_admin")) {\r
    return res.status(403).send("Agent access required.");\r
  }\r
  next();\r
}\r
\r
function requireSuperAdmin(req, res, next) {\r
  if (!req.user || req.user.role !== "super_admin") {\r
    return res.status(403).send("Platform admin only.");\r
  }\r
  next();\r
}\r
\r
async function requireCompanyActive(req, res, next) {\r
  if (req.user && req.user.role === "super_admin") return next();\r
\r
  // Reuse req.company already loaded by the session middleware — avoids a redundant DB query per request\r
  const company = req.company;\r
  if (!company) {\r
    return res.status(402).send(renderBillingGate(req.user));\r
  }\r
\r
  if (company.plan === "pending_plan") {\r
    return res.redirect(303, "/billing");\r
  }\r
\r
  if (company.status === "active") {\r
    if (!company.trial_ends_at) return next();\r
    const trialEndsAt = new Date(company.trial_ends_at);\r
    if (Date.now() <= trialEndsAt.getTime()) return next();\r
    return res.status(402).send(renderBillingGate(req.user));\r
  }\r
\r
  return res.status(402).send(renderBillingGate(req.user));\r
}\r
\r
function slugify(value) {\r
  return value\r
    .toLowerCase()\r
    .replace(/[^a-z0-9\\s-]/g, "")\r
    .trim()\r
    .replace(/\\s+/g, "-");\r
}`;

if (content.includes(oldBlock)) {
  content = content.replace(oldBlock, newBlock);
  fs.writeFileSync(filePath, content, 'utf8');
  console.log('SUCCESS: Replaced corrupted block');
} else {
  console.log('ERROR: Could not find target block');
  // Debug: show what's around line 2035
  const lines = content.split('\n');
  for (let i = 2033; i < 2045 && i < lines.length; i++) {
    console.log(`Line ${i+1}: ${JSON.stringify(lines[i])}`);
  }
}
