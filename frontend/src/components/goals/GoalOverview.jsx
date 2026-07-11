import {
  Target,
  CheckCircle2,
  IndianRupee,
  TrendingUp,
} from "lucide-react";

const formatCurrency = (value) =>
  new Intl.NumberFormat("en-IN", {
    style: "currency",
    currency: "INR",
    notation: "compact",
    maximumFractionDigits: 1,
  }).format(value);

export default function GoalOverview({ goals }) {
  const totalGoals = goals.length;

  const completedGoals = goals.filter(
    (g) => g.completed
  ).length;

  const activeGoals =
    totalGoals - completedGoals;

  const totalSaved = goals.reduce(
    (sum, goal) =>
      sum + Number(goal.current_amount),
    0
  );

  const totalTarget = goals.reduce(
    (sum, goal) =>
      sum + Number(goal.target_amount),
    0
  );

  const overallProgress =
    totalTarget === 0
      ? 0
      : Math.round(
          (totalSaved / totalTarget) * 100
        );

  const cards = [
    {
      title: "Active Goals",
      value: activeGoals,
      subtitle: "Currently in progress",
      icon: Target,
      color:
        "bg-blue-100 text-blue-600",
    },
    {
      title: "Completed",
      value: completedGoals,
      subtitle: "Goals achieved",
      icon: CheckCircle2,
      color:
        "bg-green-100 text-green-600",
    },
    {
      title: "Total Saved",
      value: formatCurrency(totalSaved),
      subtitle:
        "Target " +
        formatCurrency(totalTarget),
      icon: IndianRupee,
      color:
        "bg-emerald-100 text-emerald-600",
    },
    {
      title: "Overall Progress",
      value: `${overallProgress}%`,
      subtitle:
        "Across all goals",
      icon: TrendingUp,
      color:
        "bg-purple-100 text-purple-600",
    },
  ];

  return (
    <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-4">

      {cards.map((card) => {

        const Icon = card.icon;

        return (
          <div
            key={card.title}
            className="
              group
              rounded-3xl
              bg-white
              dark:bg-gray-900
              border
              border-gray-200
              dark:border-gray-700
              p-6
              shadow-sm
              transition-all
              duration-300
              hover:-translate-y-1
              hover:shadow-xl
            "
          >

            <div className="flex items-start justify-between">

              <div>

                <p className="text-sm font-medium text-gray-500">
                  {card.title}
                </p>

                <h2 className="mt-3 text-3xl font-bold text-gray-900 dark:text-white">
                  {card.value}
                </h2>

                <p className="mt-3 text-sm text-gray-500">
                  {card.subtitle}
                </p>

              </div>

              <div
                className={`h-14 w-14 rounded-2xl flex items-center justify-center ${card.color}`}
              >
                <Icon size={26} />
              </div>

            </div>

          </div>
        );
      })}
    </div>
  );
}