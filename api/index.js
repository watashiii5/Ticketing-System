const { app, initializeDatabase } = require("../src/server");

let initialized = false;
let initError = null;

module.exports = async (req, res) => {
  if (req.url === "/api/health") {
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({
      ok: true,
      hasDbUrl: !!(process.env.SUPABASE_DATABASE_URL || process.env.DATABASE_URL),
      initialized,
      initError,
      nodeEnv: process.env.NODE_ENV,
      vercel: process.env.VERCEL,
    }));
    return;
  }

  if (!process.env.SUPABASE_DATABASE_URL && !process.env.DATABASE_URL) {
    if (!res.headersSent) {
      res.statusCode = 500;
      res.setHeader("Content-Type", "text/plain");
      res.end("Missing database URL. Set SUPABASE_DATABASE_URL or DATABASE_URL in Vercel environment variables.");
    }
    return;
  }

  if (initError) {
    if (!res.headersSent) {
      res.statusCode = 500;
      res.setHeader("Content-Type", "text/plain");
      res.end("Database initialization failed: " + initError);
    }
    return;
  }

  if (!initialized) {
    try {
      await Promise.race([
        initializeDatabase(),
        new Promise((_, reject) => setTimeout(() => reject(new Error("DB init timed out after 20s")), 20000)),
      ]);
      initialized = true;
    } catch (err) {
      initError = err.message;
      console.error("DB init error on cold start:", err.message);
      if (!res.headersSent) {
        res.statusCode = 500;
        res.setHeader("Content-Type", "text/plain");
        res.end("Database initialization failed: " + err.message);
      }
      return;
    }
  }

  await new Promise((resolve) => {
    res.on("finish", resolve);
    res.on("close", resolve);
    try {
      app(req, res);
    } catch (err) {
      console.error("Express sync error:", err.message);
      if (!res.headersSent) {
        res.statusCode = 500;
        res.end("Internal server error");
      }
      resolve();
    }
  });
};
