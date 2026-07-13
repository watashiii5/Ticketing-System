const { app, initializeDatabase } = require("../src/server");

let initialized = false;

module.exports = async (req, res) => {
  console.log("VERCEL_URL:", req.url);
  console.log("VERCEL_METHOD:", req.method);
  console.log("VERCEL_HEADERS:", JSON.stringify({ host: req.headers.host, "x-forwarded-host": req.headers["x-forwarded-host"], "x-forwarded-proto": req.headers["x-forwarded-proto"] }));

  if (!initialized) {
    try {
      await initializeDatabase();
      initialized = true;
    } catch (err) {
      console.error("DB init error on cold start:", err.message);
    }
  }

  await new Promise((resolve) => {
    res.on("finish", resolve);
    app(req, res);
  });
};
