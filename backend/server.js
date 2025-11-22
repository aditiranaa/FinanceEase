/* FinanceEase full backend (SQLite + Knex + JWT) */
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const Knex = require('knex');

const PORT = process.env.PORT || 4001;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret_change_me';
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '10', 10);

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// serve static frontend
app.use(express.static(path.join(__dirname, 'public')));

// Health check endpoint (works without auth)
app.get('/api/health', (req, res) => {
  res.json({ ok: true, status: "Backend is alive on Vercel 🚀" });
});


// --- Knex / SQLite setup
// --- Knex / DB setup ---
const IS_VERCEL = process.env.VERCEL === '1';

// Use a writeable dir on Vercel, normal dir locally
const DB_DIR = IS_VERCEL
  ? path.join('/tmp', 'data')
  : path.join(__dirname, 'data');

if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });

let dbConfig;

// If DATABASE_URL provided, assume Postgres
if (process.env.DATABASE_URL) {
  dbConfig = {
    client: process.env.DATABASE_CLIENT || 'pg',
    connection: process.env.DATABASE_URL,
    pool: { min: 2, max: 10 }
  };
} else {
  // Otherwise fall back to SQLite everywhere
  dbConfig = {
    client: 'sqlite3',
    connection: {
      filename: path.join(DB_DIR, 'finance.db')
    },
    useNullAsDefault: true
  };
}


// Create a singleton Knex instance so serverless cold-starts don't create many pools
if (!global.__knex) {
  global.__knex = Knex(dbConfig);
}
const knex = global.__knex;
// -----------------------------------------------------------

// Auto-create tables if they don't exist
async function ensureSchema() {
  if (!(await knex.schema.hasTable('users'))) {
    await knex.schema.createTable('users', t => {
      t.string('id').primary();
      t.string('email').notNullable().unique();
      t.string('password_hash').notNullable();
      t.string('name').nullable();
      t.timestamp('created_at').defaultTo(knex.fn.now());
    });
  }

  if (!(await knex.schema.hasTable('transactions'))) {
    await knex.schema.createTable('transactions', t => {
      t.string('id').primary();
      t.string('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
      t.decimal('amount', 12, 2).notNullable();
      t.date('date').notNullable();
      t.string('description').notNullable();
      t.string('category').notNullable();
      t.timestamp('created_at').defaultTo(knex.fn.now());
      t.timestamp('updated_at').nullable();
    });
  }

  if (!(await knex.schema.hasTable('budgets'))) {
    await knex.schema.createTable('budgets', t => {
      t.string('id').primary();
      t.string('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
      t.string('category').notNullable();
      t.decimal('limit', 12, 2).defaultTo(0);
      t.decimal('spent', 12, 2).defaultTo(0);
      t.timestamp('created_at').defaultTo(knex.fn.now());
    });
  }

  if (!(await knex.schema.hasTable('goals'))) {
    await knex.schema.createTable('goals', t => {
      t.string('id').primary();
      t.string('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
      t.string('name').notNullable();
      t.decimal('target', 12, 2).defaultTo(0);
      t.decimal('saved', 12, 2).defaultTo(0);
      t.date('due_date').nullable();
      t.timestamp('created_at').defaultTo(knex.fn.now());
    });
  }

  if (!(await knex.schema.hasTable('subscriptions'))) {
    await knex.schema.createTable('subscriptions', t => {
      t.string('id').primary();
      t.string('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
      t.string('name').notNullable();
      t.string('category').defaultTo('Other');
      t.decimal('amount', 12, 2).defaultTo(0);
      t.string('frequency').defaultTo('Monthly');
      t.date('next_due').nullable();
      t.timestamp('created_at').defaultTo(knex.fn.now());
    });
  }

  if (!(await knex.schema.hasTable('earnings'))) {
    await knex.schema.createTable('earnings', t => {
      t.string('id').primary();
      t.string('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
      t.string('source').notNullable();
      t.decimal('amount', 12, 2).defaultTo(0);
      t.timestamp('created_at').defaultTo(knex.fn.now());
    });
  }

  // New: cached_metrics table to persist most recent computed metrics
  if (!(await knex.schema.hasTable('cached_metrics'))) {
    await knex.schema.createTable('cached_metrics', t => {
      t.string('id').primary();
      t.string('user_id').notNullable().unique().references('id').inTable('users').onDelete('CASCADE');
      t.text('metrics_json'); // store JSON string
      t.timestamp('updated_at').defaultTo(knex.fn.now());
    });
  }
}

ensureSchema().catch(err => {
  console.error('Error creating schema', err);
// Don't kill the process on serverless
});

// --- Auth helpers
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

async function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing token' });
  const token = auth.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await knex('users').where({ id: payload.id }).first();
    if (!user) return res.status(401).json({ error: 'Invalid token (user not found)' });
    req.user = { id: user.id, email: user.email, name: user.name };
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// --- Metric recompute helper (new)
// This computes the same metrics as /api/metrics and upserts into cached_metrics
async function recomputeMetrics(userId) {
  try {
    const now = new Date();

    // totals (expenses + income)
    const [txSumRow] = await knex('transactions').where({ user_id: userId }).sum({ total: 'amount' }).limit(1);
    const [earnSumRow] = await knex('earnings').where({ user_id: userId }).sum({ total: 'amount' }).limit(1);

    const totalExpenses = Number(txSumRow?.total || 0);
    const totalIncome = Number(earnSumRow?.total || 0);

    // month-to-date
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
    const monthStartISO = monthStart.toISOString().slice(0,10);
    const [mtdRow] = await knex('transactions')
      .where({ user_id: userId })
      .andWhere('date', '>=', monthStartISO)
      .sum({ monthlyExpenses: 'amount' })
      .limit(1);
    const monthlyExpenses = Number(mtdRow?.monthlyExpenses || 0);

    // dailyBurn = month-to-date / daysPassed
    const daysPassed = now.getDate() || 1;
    const dailyBurn = daysPassed ? (monthlyExpenses / daysPassed) : 0;

    // upcoming bills (next 30 days)
    const horizon = new Date(now.getTime() + 30*24*3600*1000);
    const horizonISO = horizon.toISOString().slice(0,10);
    const upcomingRows = await knex('subscriptions')
      .where({ user_id: userId })
      .andWhere('next_due', '>=', now.toISOString().slice(0,10))
      .andWhere('next_due', '<=', horizonISO);

    const upcomingTotal = upcomingRows.reduce((s,r) => s + Number(r.amount || 0), 0);

    // savings goal: pick named 'Laptop Fund' if present else first goal
    const goals = await knex('goals').where({ user_id: userId }).orderBy('id', 'asc');
    let selectedGoal = null;
    if (goals && goals.length) {
      selectedGoal = goals.find(g => (g.name || '').toLowerCase().includes('laptop')) || goals[0];
    }
    const savingsGoal = selectedGoal ? {
      name: selectedGoal.name,
      target: Number(selectedGoal.target || selectedGoal.amount || 0),
      saved: Number(selectedGoal.saved || 0),
      percent: selectedGoal.target ? (Number(selectedGoal.saved || 0) / Number(selectedGoal.target)) * 100 : 0
    } : { name: null, target: 0, saved: 0, percent: 0 };

    const metrics = {
      totalExpenses,
      totalIncome,
      monthlyExpenses,
      dailyBurn,
      upcoming: { count: upcomingRows.length, total: upcomingTotal },
      savingsGoal,
      computed_at: new Date().toISOString()
    };

    // upsert into cached_metrics
    const existing = await knex('cached_metrics').where({ user_id: userId }).first();
    if (existing) {
      await knex('cached_metrics').where({ user_id: userId }).update({
        metrics_json: JSON.stringify(metrics),
        updated_at: knex.fn.now()
      });
    } else {
      await knex('cached_metrics').insert({
        id: uuidv4(),
        user_id: userId,
        metrics_json: JSON.stringify(metrics),
        updated_at: knex.fn.now()
      });
    }

    return metrics;
  } catch (err) {
    console.error('recomputeMetrics error for user', userId, err);
    throw err;
  }
}

// --- AUTH ROUTES
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });
    const existing = await knex('users').where({ email }).first();
    if (existing) return res.status(409).json({ error: 'User already exists' });
    const hashed = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const id = uuidv4();
    await knex('users').insert({ id, email, password_hash: hashed, name: name || null });
    const token = signToken({ id, email });
    // initialize cached metrics for new user (empty)
    await knex('cached_metrics').insert({
      id: uuidv4(),
      user_id: id,
      metrics_json: JSON.stringify({
        totalExpenses: 0, totalIncome: 0, monthlyExpenses: 0, dailyBurn: 0, upcoming: { count:0, total:0 },
        savingsGoal: { name: null, target:0, saved:0, percent:0 }, computed_at: new Date().toISOString()
      }),
      updated_at: knex.fn.now()
    });
    res.status(201).json({ user: { id, email, name: name || null }, token });
  } catch (err) {
    console.error('register error', err);
    res.status(500).json({ error: 'server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });
    const user = await knex('users').where({ email }).first();
    if (!user) return res.status(401).json({ error: 'invalid credentials' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });
    const token = signToken({ id: user.id, email: user.email });
    res.json({ user: { id: user.id, email: user.email, name: user.name }, token });
  } catch (err) {
    console.error('login error', err);
    res.status(500).json({ error: 'server error' });
  }
});

// --- CRUD helpers for per-user resources
function makeRouterFor(tableName, requiredFields = []) {
  const router = express.Router();

  router.get('/', requireAuth, async (req, res) => {
    const items = await knex(tableName).where({ user_id: req.user.id }).orderBy('created_at', 'desc');
    res.json(items);
  });

  router.post('/', requireAuth, async (req, res) => {
    try {
      const data = req.body || {};
      for (const f of requiredFields) if (data[f] === undefined) return res.status(400).json({ error: `${f} required` });
      const id = data.id || uuidv4();
      const row = { ...data, id, user_id: req.user.id };
      await knex(tableName).insert(row);
      const inserted = await knex(tableName).where({ id }).first();

      // Recompute metrics after change (important for "auto update" requirement)
      try { await recomputeMetrics(req.user.id); } catch (e) { console.error('recompute on post failed', e); }

      res.status(201).json(inserted);
    } catch (err) {
      console.error('post error', err);
      res.status(500).json({ error: 'server error' });
    }
  });

  router.get('/:id', requireAuth, async (req, res) => {
    const row = await knex(tableName).where({ id: req.params.id, user_id: req.user.id }).first();
    if (!row) return res.status(404).json({ error: 'not found' });
    res.json(row);
  });

  router.put('/:id', requireAuth, async (req, res) => {
    try {
      const updated = { ...req.body, updated_at: knex.fn.now() };
      await knex(tableName).where({ id: req.params.id, user_id: req.user.id }).update(updated);
      const row = await knex(tableName).where({ id: req.params.id, user_id: req.user.id }).first();
      if (!row) return res.status(404).json({ error: 'not found' });

      // Recompute metrics after change
      try { await recomputeMetrics(req.user.id); } catch (e) { console.error('recompute on put failed', e); }

      res.json(row);
    } catch (err) {
      console.error('put error', err);
      res.status(500).json({ error: 'server error' });
    }
  });

  router.delete('/:id', requireAuth, async (req, res) => {
    const row = await knex(tableName).where({ id: req.params.id, user_id: req.user.id }).first();
    if (!row) return res.status(404).json({ error: 'not found' });
    await knex(tableName).where({ id: req.params.id, user_id: req.user.id }).del();

    // Recompute metrics after delete
    try { await recomputeMetrics(req.user.id); } catch (e) { console.error('recompute on delete failed', e); }

    res.json({ removed: row });
  });

  return router;
}

// Register routers
app.use('/api/transactions', makeRouterFor('transactions', ['amount','date','description','category']));
app.use('/api/budgets', makeRouterFor('budgets', ['category']));
app.use('/api/goals', makeRouterFor('goals', ['name','due_date'])); // target/saved optional
app.use('/api/subscriptions', makeRouterFor('subscriptions', ['name','next_due']));
app.use('/api/earnings', makeRouterFor('earnings', ['source']));

// metrics (per-user) 
// Now tries to serve cached metrics (keeps them fresh via recomputeMetrics on writes)
app.get('/api/metrics', requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;

    // Try cached metrics first
    const cached = await knex('cached_metrics').where({ user_id: userId }).first();
    if (cached && cached.metrics_json) {
      try {
        const parsed = JSON.parse(cached.metrics_json);
        return res.json(parsed);
      } catch (e) {
        console.warn('failed to parse cached metrics JSON, falling back to live compute', e);
      }
    }

    // Fallback: compute live and store
    const metrics = await recomputeMetrics(userId);
    res.json(metrics);
  } catch (err) {
    console.error('metrics error', err);
    res.status(500).json({ error: 'server error' });
  }
});

// AI insight mock
app.post('/api/ai-insight', requireAuth, async (req, res) => {
  const { prompt = '' } = req.body;
  const tx = await knex('transactions').where({ user_id: req.user.id });
  const total = tx.reduce((s,t) => s + Number(t.amount || 0), 0);
  const reply = [
    `You have ${tx.length} transactions totaling ₹${total.toFixed(2)}.`,
    prompt ? `Regarding: \"${prompt}\" — try cutting one recurring item and save that each month.` : `Tip: set a weekly budget and automate one saving transfer.`
  ].join(' ');
  setTimeout(() => res.json({ text: reply }), 200); // small delay for UX
});

// Fallback - Serve index.html for SPA (skip API routes)
app.use((req, res, next) => {
  if (req.path && req.path.startsWith('/api')) return next();
  const index = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(index)) return res.sendFile(index);
  return res.status(404).send('No frontend found. Put index.html in /public');
});

// Start server
// if running locally (dev) keep listening, otherwise export handler for serverless platforms
if (process.env.VERCEL === '1' || process.env.NODE_ENV === 'production') {
  // export handler for serverless
  const serverless = require('serverless-http');
  module.exports = serverless(app);
} else {
  const PORT = process.env.PORT || 4000;
  app.listen(PORT, () => {
    console.log(`FinanceEase backend listening on http://localhost:${PORT}`);
  });
}
