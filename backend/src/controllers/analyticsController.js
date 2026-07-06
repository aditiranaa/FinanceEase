const db = require("../config/db");

// ===============================
// ANALYTICS OVERVIEW
// ===============================
exports.getOverview = async (req, res) => {
  try {
    const userId = req.user.id;

    const transactions = await db("transactions")
      .where({ user_id: userId });

    const budgets = await db("budgets")
      .where({ user_id: userId });

    const goals = await db("goals")
      .where({ user_id: userId });

    const totalIncome = transactions
      .filter((t) => t.type === "income")
      .reduce((sum, t) => sum + Number(t.amount), 0);

    const totalExpense = transactions
      .filter((t) => t.type === "expense")
      .reduce((sum, t) => sum + Number(t.amount), 0);

    const savings = totalIncome - totalExpense;

    const budgetLimit = budgets.reduce(
      (sum, b) => sum + Number(b.limit),
      0
    );

    const budgetSpent = budgets.reduce(
      (sum, b) => sum + Number(b.spent),
      0
    );

    const completedGoals = goals.filter(
      (g) => g.completed
    ).length;

    res.json({
      totalIncome,
      totalExpense,
      savings,
      budgetLimit,
      budgetSpent,
      totalGoals: goals.length,
      completedGoals,
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Failed to fetch analytics overview",
    });
  }
};

// ===============================
// EXPENSE BY CATEGORY
// ===============================
exports.getExpenseByCategory = async (req, res) => {
  try {
    const expenses = await db("transactions")
      .where({
        user_id: req.user.id,
        type: "expense",
      });

    const grouped = {};

    expenses.forEach((t) => {
      grouped[t.category] =
        (grouped[t.category] || 0) +
        Number(t.amount);
    });

    const data = Object.entries(grouped).map(
      ([category, amount]) => ({
        category,
        amount,
      })
    );

    res.json(data);

  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Failed to fetch expense categories",
    });
  }
};

// ===============================
// MONTHLY TREND
// ===============================
exports.getMonthlyTrend = async (req, res) => {
  try {
    const transactions = await db("transactions")
      .where({
        user_id: req.user.id,
      })
      .orderBy("date");

    const months = {};

    transactions.forEach((t) => {
      const month = t.date
        .toISOString()
        .slice(0, 7);

      if (!months[month]) {
        months[month] = {
          month,
          income: 0,
          expense: 0,
        };
      }

      if (t.type === "income") {
        months[month].income += Number(t.amount);
      } else {
        months[month].expense += Number(t.amount);
      }
    });

    res.json(Object.values(months));

  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Failed to fetch monthly trend",
    });
  }
};

// ===============================
// SAVINGS TREND
// ===============================
exports.getSavingsTrend = async (req, res) => {
  try {
    const goals = await db("goals")
      .where({
        user_id: req.user.id,
      });

    const data = goals.map((goal) => ({
      title: goal.title,
      saved: Number(goal.current_amount),
      target: Number(goal.target_amount),
    }));

    res.json(data);

  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Failed to fetch savings trend",
    });
  }
};