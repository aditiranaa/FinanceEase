import {
  Wallet,
  TrendingDown,
  PiggyBank,
  Target,
} from "lucide-react";

import AnalyticsCard from "./AnalyticsCard";

const formatCurrency = (value) =>
  Number(value || 0).toLocaleString("en-IN", {
    style: "currency",
    currency: "INR",
    maximumFractionDigits: 0,
  });

export default function AnalyticsOverview({
  overview,
}) {
  if (!overview) return null;

  const cards = [
    {
      title: "Income",
      value: formatCurrency(
        overview.totalIncome
      ),
      subtitle: "Money Earned",
      icon: Wallet,
      iconColor: "text-emerald-600",
      iconBg:
        "bg-emerald-100 dark:bg-emerald-900/30",
    },
    {
      title: "Expenses",
      value: formatCurrency(
        overview.totalExpense
      ),
      subtitle: "Money Spent",
      icon: TrendingDown,
      iconColor: "text-red-600",
      iconBg:
        "bg-red-100 dark:bg-red-900/30",
    },
    {
      title: "Savings",
      value: formatCurrency(
        overview.savings
      ),
      subtitle: "Current Balance",
      icon: PiggyBank,
      iconColor: "text-blue-600",
      iconBg:
        "bg-blue-100 dark:bg-blue-900/30",
    },
    {
      title: "Goals",
      value: `${overview.completedGoals}/${overview.totalGoals}`,
      subtitle: "Completed",
      icon: Target,
      iconColor: "text-violet-600",
      iconBg:
        "bg-violet-100 dark:bg-violet-900/30",
    },
  ];

  return (
    <div className="grid gap-5 sm:grid-cols-2 xl:grid-cols-4">
      {cards.map((card) => (
        <AnalyticsCard
          key={card.title}
          {...card}
        />
      ))}
    </div>
  );
}