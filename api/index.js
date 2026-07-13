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
  await new Promise((resolve) => {
    res.on("finish", resolve);
    app(req, res);
  });
};
