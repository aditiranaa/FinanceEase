// api/index.js
// Vercel serverless adapter — imports your Express app and exports the handler

const serverless = require('serverless-http');
const app = require('../server'); // adjust path if your server file is named differently

module.exports = serverless(app);
  