import { IndianRupee, Wallet, TrendingDown, Percent } from "lucide-react";

const formatCurrency = (value) => {
  return Number(value || 0).toLocaleString("en-IN", {
    style: "currency",
    currency: "INR",
    maximumFractionDigits: 2,
  });
};

const StatCard = ({ title, value, icon, color }) => (
  <div className="bg-white dark:bg-gray-900 rounded-xl shadow-md border border-gray-200 dark:border-gray-800 p-5 transition hover:shadow-lg">
    <div className="flex items-center justify-between">
      <div>
        <p className="text-sm text-gray-500 dark:text-gray-400">
          {title}
        </p>

        <h2 className="mt-2 text-2xl font-bold text-gray-900 dark:text-white">
          {value}
        </h2>
      </div>

      <div
        className={`w-12 h-12 rounded-full flex items-center justify-center ${color}`}
      >
        {icon}
      </div>
    </div>
  </div>
);

export default function BudgetOverview({ budgets = [] }) {
  const totalBudget = budgets.reduce(
    (sum, budget) => sum + Number(budget.limit),
    0
  );

  const totalSpent = budgets.reduce(
    (sum, budget) => sum + Number(budget.spent),
    0
  );

  const remaining = totalBudget - totalSpent;

  const percentage =
    totalBudget === 0
      ? 0
      : Math.min(
          100,
          Math.round((totalSpent / totalBudget) * 100)
        );

  return (
    <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-4 mb-4">
      <StatCard
        title="Total Budget"
        value={formatCurrency(totalBudget)}
        color="bg-blue-100 text-blue-600"
        icon={<Wallet size={24} />}
      />

      <StatCard
        title="Spent"
        value={formatCurrency(totalSpent)}
        color="bg-red-100 text-red-600"
        icon={<TrendingDown size={24} />}
      />

      <StatCard
        title="Remaining"
        value={formatCurrency(remaining)}
        color={
          remaining >= 0
            ? "bg-green-100 text-green-600"
            : "bg-red-100 text-red-600"
        }
        icon={<IndianRupee size={24} />}
      />

      <StatCard
        title="Budget Used"
        value={`${percentage}%`}
        color={
          percentage >= 90
            ? "bg-red-100 text-red-600"
            : percentage >= 70
            ? "bg-yellow-100 text-yellow-600"
            : "bg-green-100 text-green-600"
        }
        icon={<Percent size={24} />}
      />
    </div>
  );
}