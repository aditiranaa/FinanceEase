
require('dotenv').config();

const express = require('express');
const app = express();

const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const ensureSchema = require('./src/config/schema');

const testRoutes = require('./src/routes/test.routes');
const authRoutes = require('./src/routes/auth.routes');
const transactionRoutes = require('./src/routes/transaction.routes');
const aiRoutes = require('./src/routes/aiRoutes');
const notificationRoutes = require("./src/routes/notification.routes");

const makeRouterFor = require('./src/routes/crud.factory');

// MIDDLEWARE
app.use(helmet());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});

app.use(limiter);

app.use(cors());

app.use(express.json());

app.use(
  express.urlencoded({
    extended: false,
  })
);

// TEST
app.use(
  "/api",
  testRoutes
);

// AUTH
app.use(
  "/api/auth",
  authRoutes
);

// TRANSACTIONS
app.use(
  "/api/transactions",
  transactionRoutes
);

// BUDGETS
app.use(
  "/api/budgets",
  makeRouterFor(
    "budgets",
    [
      "category",
      "amount",
    ]
  )
);

// GOALS
app.use(
  "/api/goals",
  makeRouterFor(
    "goals",
    [
      "title",
      "target_amount",
      "current_amount",
    ]
  )
);

// SUBSCRIPTIONS
app.use(
  "/api/subscriptions",
  makeRouterFor(
    "subscriptions",
    [
      "name",
      "next_due",
    ]
  )
);

// EARNINGS
app.use(
  "/api/earnings",
  makeRouterFor(
    "earnings",
    [
      "source",
    ]
  )
);

// AI
app.use(
  "/api/ai-insight",
  aiRoutes
);

// HEALTH CHECK
app.get(
  "/api/health",
  (req, res) => {

    res.json({
      ok: true,
      status:
        "Backend is alive on Vercel 🚀",
    });

  }
);

// NOTIFICATIONS 
app.use(
  "/api/notifications",
  notificationRoutes
);

const PORT =
  process.env.PORT || 4000;

ensureSchema()
  .then(() => {

    console.log(
      "Schema initialized"
    );

    app.listen(
      PORT,
      () => {

        console.log(
          `FinanceEase backend listening on http://localhost:${PORT}`
        );

      }
    );

  })
  .catch(err => {

    console.error(
      "Schema error",
      err
    );

  });

