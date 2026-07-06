const express = require("express");
const router = express.Router();

const auth = require("../middleware/auth");

const {
  getOverview,
  getExpenseByCategory,
  getMonthlyTrend,
  getSavingsTrend,
} = require("../controllers/analyticsController");

router.use(auth);

router.get("/overview", getOverview);

router.get(
  "/expenses/category",
  getExpenseByCategory
);

router.get(
  "/monthly-trend",
  getMonthlyTrend
);

router.get(
  "/savings-trend",
  getSavingsTrend
);

module.exports = router;