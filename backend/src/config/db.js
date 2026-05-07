const path = require('path');
const fs = require('fs');
const Knex  = require('knex');

const IS_VERCEL = process.env.VERCEL === '1';

// Writable directory
const DB_DIR = IS_VERCEL
  ? path.join('/tmp', 'data')
  : path.join(__dirname, '../../data');

if (!fs.existsSync(DB_DIR)) {
  fs.mkdirSync(DB_DIR, { recursive: true });
}

let dbConfig;

// PostgreSQL if DATABASE_URL exists
if (process.env.DATABASE_URL) {
  dbConfig = {
    client: process.env.DATABASE_CLIENT || 'pg',
    connection: process.env.DATABASE_URL,
    pool: {
      min: 2,
      max: 10
    }
  };
} else {
  // SQLite fallback
  dbConfig = {
    client: 'sqlite3',
    connection: {
      filename: path.join(DB_DIR, 'finance.db')
    },
    useNullAsDefault: true
  };
}

// Singleton knex instance
if (!global.__knex) {
  global.__knex = Knex(dbConfig);
}

const knex = global.__knex;

module.exports = knex;
