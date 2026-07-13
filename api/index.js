// Vercel serverless entry point for the ticketing app
// Uses serverless-http to wrap Express for serverless compatibility
const serverless = require("serverless-http");
const { app, initializeDatabase } = require("../src/server");

// Initialize database on cold start
let initialized = false;
const handler = serverless(app);

module.exports = async (req, res) => {
  if (!initialized) {
    try {
      await initializeDatabase();
      initialized = true;
    } catch (err) {
      console.error("DB init error on cold start:", err.message);
      // Even if DB init fails, still try to handle the request
    }
  }
  
  return handler(req, res);
};