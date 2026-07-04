const express = require("express");

const router = express.Router();

const auth = require("../middleware/auth");

const budgetController = require("../controllers/budgetController");

// =============================
// GET
// =============================

router.get(
  "/",
  auth,
  budgetController.getBudgets
);

router.get(
  "/summary",
  auth,
  budgetController.getSummary
);

router.get(
  "/:id",
  auth,
  budgetController.getBudget
);

// =============================
// POST
// =============================

router.post(
  "/",
  auth,
  budgetController.createBudget
);

// =============================
// PUT
// =============================

router.put(
  "/:id",
  auth,
  budgetController.updateBudget
);

// =============================
// DELETE
// =============================

router.delete(
  "/:id",
  auth,
  budgetController.deleteBudget
);

module.exports = router;