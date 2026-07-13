const { app, initializeDatabase } = require("../src/server");

let initialized = false;

module.exports = async (req, res) => {
  if (!initialized) {
    try {
      await initializeDatabase();
      initialized = true;
    } catch (err) {
      console.error("DB init error on cold start:", err.message);
    }
  }

  const originalPath =
    req.headers["x-matched-path"] ||
    req.headers["x-forwarded-uri"] ||
    req.headers["x-original-url"] ||
    req.headers["x-rewrite-url"];

  if (originalPath && originalPath !== req.url) {
    req.url = originalPath.startsWith("/") ? originalPath : "/" + originalPath;
  }

  await new Promise((resolve) => {
    res.on("finish", resolve);
    app(req, res);
  });
};
