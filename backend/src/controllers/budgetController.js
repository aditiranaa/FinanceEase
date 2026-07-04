const db = require("../config/db");
const { v4: uuid } = require("uuid");

// ===============================
// GET ALL BUDGETS
// ===============================
exports.getBudgets = async (req, res) => {
  try {
    const budgets = await db("budgets")
      .where({ user_id: req.user.id })
      .orderBy("created_at", "desc");

    res.json(budgets);
  } catch (err) {
    console.error(err);
    res.status(500).json({
      message: "Failed to fetch budgets",
    });
  }
};

// ===============================
// GET SINGLE BUDGET
// ===============================
exports.getBudget = async (req, res) => {
  try {
    const budget = await db("budgets")
      .where({
        id: req.params.id,
        user_id: req.user.id,
      })
      .first();

    if (!budget) {
      return res.status(404).json({
        message: "Budget not found",
      });
    }

    res.json(budget);
  } catch (err) {
    console.error(err);
    res.status(500).json({
      message: "Failed to fetch budget",
    });
  }
};

// ===============================
// CREATE BUDGET
// ===============================
exports.createBudget = async (req, res) => {
  try {
    const {
      category,
      limit,
      spent,
      month,
    } = req.body;

    // ============================
    // Validation
    // ============================

    if (!category || !limit) {
      return res.status(400).json({
        message: "Category and budget limit are required.",
      });
    }

    if (Number(limit) < 0) {
      return res.status(400).json({
        message: "Budget limit cannot be negative.",
      });
    }

    if (Number(spent || 0) < 0) {
      return res.status(400).json({
        message: "Spent amount cannot be negative.",
      });
    }

    // ============================
    // Prevent duplicate budgets
    // ============================

    const existing = await db("budgets")
      .where({
        user_id: req.user.id,
        category,
        month,
      })
      .first();

    if (existing) {
      return res.status(400).json({
        message:
          "A budget for this category already exists for this month.",
      });
    }

    // ============================
    // Create budget
    // ============================

    const budget = {
      id: uuid(),
      user_id: req.user.id,
      category,
      limit,
      spent: spent || 0,
      month,
    };

    await db("budgets").insert(budget);

    res.status(201).json({
      message: "Budget created successfully",
      budget,
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Failed to create budget",
    });
  }
};

exports.updateBudget = async (req, res) => {
  try {
    const {
      category,
      limit,
      spent,
      month,
    } = req.body;

    if (!category || !limit) {
      return res.status(400).json({
        message: "Category and limit are required.",
      });
    }

    if (Number(limit) < 0 || Number(spent) < 0) {
      return res.status(400).json({
        message: "Amounts cannot be negative.",
      });
    }

    const updated = await db("budgets")
      .where({
        id: req.params.id,
        user_id: req.user.id,
      })
      .update({
        category,
        limit,
        spent,
        month,
        updated_at: db.fn.now(),
      });

    if (!updated) {
      return res.status(404).json({
        message: "Budget not found.",
      });
    }

    res.json({
      message: "Budget updated successfully.",
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Failed to update budget.",
    });
  }
};

// ===============================
// DELETE BUDGET
// ===============================
exports.deleteBudget = async (req, res) => {
  try {
    const deleted = await db("budgets")
      .where({
        id: req.params.id,
        user_id: req.user.id,
      })
      .del();

    if (!deleted) {
      return res.status(404).json({
        message: "Budget not found",
      });
    }

    res.json({
      message: "Budget deleted",
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Failed to delete budget",
    });
  }
};

// ===============================
// BUDGET SUMMARY
// ===============================
exports.getSummary = async (req, res) => {
  try {
    const budgets = await db("budgets")
      .where({
        user_id: req.user.id,
      });

    const totalBudget = budgets.reduce(
      (sum, b) => sum + Number(b.limit),
      0
    );

    const totalSpent = budgets.reduce(
      (sum, b) => sum + Number(b.spent),
      0
    );

    const remaining =
      totalBudget - totalSpent;

    const alerts = budgets.filter((b) => {
      if (Number(b.limit) === 0) return false;

      return (
        (Number(b.spent) /
          Number(b.limit)) *
          100 >=
        80
      );
    });

    res.json({
      totalBudget,
      totalSpent,
      remaining,
      alerts,
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      message:
        "Failed to load budget summary",
    });
  }
};