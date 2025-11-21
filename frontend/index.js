/*
  Vercel serverless adapter for FinanceEase Express app
  Wraps your exported Express app (server.js) with serverless-http.
*/
const serverless = require('serverless-http');
const app = require('../server'); // adjust if server file has different name

module.exports = serverless(app);
