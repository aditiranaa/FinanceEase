import {
  IndianRupee,
  Wallet,
  TrendingDown,
  Percent,
} from "lucide-react";

const formatCurrency = (value) =>
  Number(value || 0).toLocaleString("en-IN", {
    style: "currency",
    currency: "INR",
    maximumFractionDigits: 2,
  });

function StatCard({
  title,
  value,
  icon,
  iconClass,
}) {
  return (
    <div className="rounded-2xl border border-gray-100 bg-white p-6 shadow-sm transition-all duration-200 hover:shadow-md">
      <div className="flex items-center justify-between">
        <div className="min-w-0">
          <p className="text-sm font-medium text-gray-500">
            {title}
          </p>

          <h2 className="mt-3 text-3xl font-bold tracking-tight text-gray-900">
            {value}
          </h2>
        </div>

        <div
          className={`flex h-14 w-14 items-center justify-center rounded-2xl ${iconClass}`}
        >
          {icon}
        </div>
      </div>
    </div>
  );
}

export default function BudgetOverview({
  budgets = [],
}) {
  const totalBudget = budgets.reduce(
    (sum, budget) => sum + Number(budget.limit || 0),
    0
  );

  const totalSpent = budgets.reduce(
    (sum, budget) => sum + Number(budget.spent || 0),
    0
  );

  const remaining = totalBudget - totalSpent;

  const percentage =
    totalBudget === 0
      ? 0
      : Math.min(
          100,
          Math.round(
            (totalSpent / totalBudget) * 100
          )
        );

  return (
    <section className="grid gap-6 md:grid-cols-2 xl:grid-cols-4">
      <StatCard
        title="Total Budget"
        value={formatCurrency(totalBudget)}
        icon={<Wallet size={28} />}
        iconClass="bg-blue-100 text-blue-600"
      />

      <StatCard
        title="Spent"
        value={formatCurrency(totalSpent)}
        icon={<TrendingDown size={28} />}
        iconClass="bg-red-100 text-red-600"
      />

      <StatCard
        title="Remaining"
        value={formatCurrency(remaining)}
        icon={<IndianRupee size={28} />}
        iconClass={
          remaining >= 0
            ? "bg-emerald-100 text-emerald-600"
            : "bg-red-100 text-red-600"
        }
      />

      <StatCard
        title="Budget Used"
        value={`${percentage}%`}
        icon={<Percent size={28} />}
        iconClass={
          percentage >= 90
            ? "bg-red-100 text-red-600"
            : percentage >= 70
            ? "bg-amber-100 text-amber-600"
            : "bg-emerald-100 text-emerald-600"
        }
      />
    </section>
  );
}