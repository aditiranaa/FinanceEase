import {
  Target,
  CheckCircle2,
  IndianRupee,
  TrendingUp,
} from "lucide-react";

const formatCurrency = (value) =>
  Number(value || 0).toLocaleString("en-IN", {
    style: "currency",
    currency: "INR",
    maximumFractionDigits: 0,
  });

function StatCard({
  title,
  value,
  subtitle,
  icon,
  color,
}) {
  return (
    <div className="bg-white rounded-2xl shadow-sm border border-gray-100 p-6 hover:shadow-md transition">

      <div className="flex items-center justify-between">

        <div>

          <p className="text-sm text-gray-500">
            {title}
          </p>

          <h2 className="mt-2 text-3xl font-bold text-gray-900">
            {value}
          </h2>

          <p className="mt-2 text-sm text-gray-400">
            {subtitle}
          </p>

        </div>

        <div
          className={`w-14 h-14 rounded-2xl flex items-center justify-center ${color}`}
        >
          {icon}
        </div>

      </div>

    </div>
  );
}

export default function GoalOverview({
  goals = [],
}) {
  const activeGoals =
    goals.filter((g) => !g.completed);

  const completedGoals =
    goals.filter((g) => g.completed);

  const totalSaved =
    goals.reduce(
      (sum, goal) =>
        sum + Number(goal.current_amount),
      0
    );

  const totalTarget =
    goals.reduce(
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

  return (
    <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-4">

      <StatCard
        title="Active Goals"
        value={activeGoals.length}
        subtitle="Currently in progress"
        color="bg-blue-100 text-blue-600"
        icon={<Target size={28} />}
      />

      <StatCard
        title="Completed"
        value={completedGoals.length}
        subtitle="Goals achieved"
        color="bg-green-100 text-green-600"
        icon={<CheckCircle2 size={28} />}
      />

      <StatCard
        title="Total Saved"
        value={formatCurrency(totalSaved)}
        subtitle={`Target ${formatCurrency(
          totalTarget
        )}`}
        color="bg-emerald-100 text-emerald-600"
        icon={<IndianRupee size={28} />}
      />

      <StatCard
        title="Overall Progress"
        value={`${overallProgress}%`}
        subtitle="Across all goals"
        color="bg-violet-100 text-violet-600"
        icon={<TrendingUp size={28} />}
      />

    </div>
  );
}