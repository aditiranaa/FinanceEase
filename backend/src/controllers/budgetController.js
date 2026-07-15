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
      spent = 0,
    } = req.body;

    if (!category || limit === undefined || limit === null) {
      return res.status(400).json({
        message: "Category and budget limit are required.",
      });
    }

    if (Number(limit) < 0) {
      return res.status(400).json({
        message: "Budget limit cannot be negative.",
      });
    }

    if (Number(spent) < 0) {
      return res.status(400).json({
        message: "Spent amount cannot be negative.",
      });
    }

    // Prevent duplicate category budgets
    const existing = await db("budgets")
      .where({
        user_id: req.user.id,
        category,
      })
      .first();

    if (existing) {
      return res.status(400).json({
        message: "A budget for this category already exists.",
      });
    }

    const budget = {
      id: uuid(),
      user_id: req.user.id,
      category,
      limit: Number(limit),
      spent: Number(spent),
    };

    await db("budgets").insert(budget);

    res.status(201).json({
      message: "Budget created successfully.",
      budget,
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Failed to create budget.",
    });
  }
};

// ===============================
// UPDATE BUDGET
// ===============================
exports.updateBudget = async (req, res) => {
  try {
    const {
      category,
      limit,
      spent = 0,
    } = req.body;

    if (!category || limit === undefined || limit === null) {
      return res.status(400).json({
        message: "Category and budget limit are required.",
      });
    }

    if (Number(limit) < 0) {
      return res.status(400).json({
        message: "Budget limit cannot be negative.",
      });
    }

    if (Number(spent) < 0) {
      return res.status(400).json({
        message: "Spent amount cannot be negative.",
      });
    }

    const updated = await db("budgets")
      .where({
        id: req.params.id,
        user_id: req.user.id,
      })
      .update({
        category,
        limit: Number(limit),
        spent: Number(spent),
        updated_at: db.fn.now(),
      });

    if (!updated) {
      return res.status(404).json({
        message: "Budget not found.",
      });
    }

    const budget = await db("budgets")
      .where({
        id: req.params.id,
        user_id: req.user.id,
      })
      .first();

    res.json({
      message: "Budget updated successfully.",
      budget,
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
        message: "Budget not found.",
      });
    }

    res.json({
      message: "Budget deleted successfully.",
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Failed to delete budget.",
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
      (sum, budget) => sum + Number(budget.limit),
      0
    );

    const totalSpent = budgets.reduce(
      (sum, budget) => sum + Number(budget.spent),
      0
    );

    const remaining = totalBudget - totalSpent;

    const alerts = budgets.filter((budget) => {
      if (!Number(budget.limit)) return false;

      return (
        (Number(budget.spent) / Number(budget.limit)) * 100 >= 80
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
      message: "Failed to load budget summary.",
    });
  }
};