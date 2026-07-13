// Vercel serverless entry point for the ticketing app
// Simply imports and re-exports the Express app from server.js
const { app, initializeDatabase } = require("../src/server");

// Initialize database on cold start
let initialized = false;

module.exports = async (req, res) => {
  if (!initialized) {
    try {
      await initializeDatabase();
      initialized = true;
    } catch (err) {
      console.error("Initial DB init error:", err.message);
    }
  }
  
  // Handle the request using the fully configured Express app from server.js
  return app(req, res);
};