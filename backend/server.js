require('dotenv').config();

const express = require('express');
const cors = require('cors');

const helmet = require('helmet');

const rateLimit = require('express-rate-limit');

const ensureSchema = require('./src/config/schema');

const authRoutes = require('./src/routes/auth.routes');

const makeRouterFor = require('./src/routes/crud.factory');

const requireAuth = require('./src/middleware/auth');

const app = express();

app.use(helmet());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

app.use(limiter);
app.use(cors());

app.use(express.json());

app.use(express.urlencoded({ extended: false }));

// AUTH
app.use('/api/auth', authRoutes);

// CRUD ROUTES
app.use(
  '/api/transactions',
  makeRouterFor(
    'transactions',
    ['amount', 'date', 'description', 'category']
  )
);

app.use(
  '/api/budgets',
  makeRouterFor(
    'budgets',
    ['category']
  )
);

app.use(
  '/api/goals',
  makeRouterFor(
    'goals',
    ['name', 'due_date']
  )
);

app.use(
  '/api/subscriptions',
  makeRouterFor(
    'subscriptions',
    ['name', 'next_due']
  )
);

app.use(
  '/api/earnings',
  makeRouterFor(
    'earnings',
    ['source']
  )
);

// HEALTH CHECK
app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    status: 'Backend is alive on Vercel 🚀'
  });
});

// AI INSIGHT
app.post(
  '/api/ai-insight',
  requireAuth,
  async (req, res) => {
    res.json({
      text: 'AI insight endpoint working'
    });
  }
);

const PORT = process.env.PORT || 4000;

ensureSchema()
  .then(() => {
    console.log('Schema initialized');
  })
  .catch(err => {
    console.error('Schema error', err);
  });
  
app.listen(PORT, () => {
  console.log(
    `FinanceEase backend listening on http://localhost:${PORT}`
  );
});