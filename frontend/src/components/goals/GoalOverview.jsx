import { useMemo } from "react";
import {
  Target,
  CheckCircle2,
  Wallet,
  TrendingUp,
} from "lucide-react";

const formatCurrency = (amount) => {
  const value = Number(amount || 0);

  return `₹${value.toLocaleString("en-IN")}`;
};

function OverviewCard({
  title,
  value,
  subtitle,
  icon: Icon,
  iconColor,
  iconBg,
}) {
  return (
    <div
      className="
        rounded-2xl
        border
        border-gray-200
        dark:border-gray-700
        bg-white
        dark:bg-gray-900
        p-5
        shadow-sm
        transition
        hover:-translate-y-0.5
        hover:shadow-md
      "
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-gray-500">
            {title}
          </p>

          <h2 className="mt-2 text-lg font-bold text-gray-900 dark:text-white">
            {value}
          </h2>

          <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
            {subtitle}
          </p>
        </div>

        <div
          className={`
            flex
            h-12
            w-12
            items-center
            justify-center
            rounded-2xl
            ${iconBg}
          `}
        >
          <Icon
            size={22}
            className={iconColor}
          />
        </div>
      </div>
    </div>
  );
}

export default function GoalOverview({
  goals = [],
}) {
  const stats = useMemo(() => {
    const active = goals.filter(
      (goal) => !goal.completed
    ).length;

    const completed = goals.filter(
      (goal) => goal.completed
    ).length;

    const saved = goals.reduce(
      (sum, goal) =>
        sum + Number(goal.current_amount || 0),
      0
    );

    const target = goals.reduce(
      (sum, goal) =>
        sum + Number(goal.target_amount || 0),
      0
    );

    const progress =
      target > 0
        ? Math.round((saved / target) * 100)
        : 0;

    return {
      active,
      completed,
      saved,
      target,
      progress,
    };
  }, [goals]);

  const cards = [
    {
      title: "Active",
      value: stats.active,
      subtitle: "Goals in progress",
      icon: Target,
      iconColor: "text-blue-600",
      iconBg:
        "bg-blue-100 dark:bg-blue-900/30",
    },
    {
      title: "Completed",
      value: stats.completed,
      subtitle: "Goals achieved",
      icon: CheckCircle2,
      iconColor: "text-green-600",
      iconBg:
        "bg-green-100 dark:bg-green-900/30",
    },
    {
      title: "Saved",
      value: formatCurrency(stats.saved),
      subtitle: `Target ${formatCurrency(
        stats.target
      )}`,
      icon: Wallet,
      iconColor: "text-emerald-600",
      iconBg:
        "bg-emerald-100 dark:bg-emerald-900/30",
    },
    {
      title: "Progress",
      value: `${stats.progress}%`,
      subtitle: "Overall completion",
      icon: TrendingUp,
      iconColor: "text-purple-600",
      iconBg:
        "bg-purple-100 dark:bg-purple-900/30",
    },
  ];

  return (
    <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
      {cards.map((card) => (
        <OverviewCard
          key={card.title}
          {...card}
        />
      ))}
    </div>
  );
}