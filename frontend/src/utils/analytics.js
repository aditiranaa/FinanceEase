export const formatCurrency = (value = 0) =>
  Number(value).toLocaleString("en-IN", {
    style: "currency",
    currency: "INR",
    maximumFractionDigits: 0,
  });

export const formatCompactCurrency = (value = 0) => {
  const amount = Number(value);

  if (amount >= 10000000) {
    return `₹${(amount / 10000000).toFixed(1)}Cr`;
  }

  if (amount >= 100000) {
    return `₹${(amount / 100000).toFixed(1)}L`;
  }

  if (amount >= 1000) {
    return `₹${(amount / 1000).toFixed(1)}K`;
  }

  return `₹${amount.toLocaleString("en-IN")}`;
};

export const calculateSavings = (
  income = 0,
  expense = 0
) => Number(income) - Number(expense);

export const calculateSavingsRate = (
  income = 0,
  expense = 0
) => {
  const totalIncome = Number(income);

  if (totalIncome === 0) return 0;

  return Math.round(
    ((totalIncome - Number(expense)) /
      totalIncome) *
      100
  );
};

export const groupTransactionsByMonth = (
  transactions = []
) => {
  const grouped = {};

  transactions.forEach((transaction) => {
    const month = new Date(
      transaction.date
    ).toLocaleString("en-IN", {
      month: "short",
    });

    if (!grouped[month]) {
      grouped[month] = {
        month,
        income: 0,
        expense: 0,
      };
    }

    if (transaction.type === "income") {
      grouped[month].income += Number(
        transaction.amount
      );
    } else {
      grouped[month].expense += Number(
        transaction.amount
      );
    }
  });

  return Object.values(grouped);
};

export const groupTransactionsByCategory = (
  transactions = []
) => {
  const grouped = {};

  transactions
    .filter((t) => t.type === "expense")
    .forEach((transaction) => {
      const category =
        transaction.category || "Other";

      grouped[category] =
        (grouped[category] || 0) +
        Number(transaction.amount);
    });

  return Object.entries(grouped).map(
    ([category, amount]) => ({
      category,
      amount,
    })
  );
};

export const getIncomeExpenseSeries = (
  monthlyData = []
) =>
  monthlyData.map((item) => ({
    month: item.month,
    income: Number(item.income || 0),
    expense: Number(item.expense || 0),
  }));

export const getSavingsSeries = (
  goals = []
) =>
  goals.map((goal) => ({
    title: goal.title,
    saved: Number(
      goal.current_amount || 0
    ),
    target: Number(
      goal.target_amount || 0
    ),
  }));

export const getOverviewStats = (
  overview = {}
) => ({
  totalIncome: Number(
    overview.totalIncome || 0
  ),
  totalExpense: Number(
    overview.totalExpense || 0
  ),
  savings: calculateSavings(
    overview.totalIncome,
    overview.totalExpense
  ),
  savingsRate: calculateSavingsRate(
    overview.totalIncome,
    overview.totalExpense
  ),
  completedGoals: Number(
    overview.completedGoals || 0
  ),
  totalGoals: Number(
    overview.totalGoals || 0
  ),
});