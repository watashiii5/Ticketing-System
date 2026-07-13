const { app, initializeDatabase } = require("../src/server");

let initialized = false;

module.exports = async (req, res) => {
  if (!initialized) {
    try {
      await initializeDatabase();
      initialized = true;
    } catch (err) {
      console.error("DB init error on cold start:", err.message);
      if (!res.headersSent) {
        res.statusCode = 500;
        res.end("Database initialization failed");
      }
      return;
    }
  }

  // Removed originalPath rewriting logic to prevent routing issues.

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
