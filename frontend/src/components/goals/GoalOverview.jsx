import { Target, CheckCircle, IndianRupee, TrendingUp } from "lucide-react";

const formatCurrency = (value) =>
  Number(value || 0).toLocaleString("en-IN", {
    style: "currency",
    currency: "INR",
    maximumFractionDigits: 0,
  });

const StatCard = ({ title, value, icon, color }) => (
  <div className="bg-white dark:bg-gray-900 rounded-xl shadow-md border border-gray-200 dark:border-gray-800 p-5 transition hover:shadow-lg">
    <div className="flex items-center justify-between">
      <div>
        <p className="text-sm text-gray-500 dark:text-gray-400">{title}</p>
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

export default function GoalOverview({ goals = [] }) {
  const active = goals.filter((g) => !g.completed);
  const completed = goals.filter((g) => g.completed);

  const totalSaved = goals.reduce(
    (sum, g) => sum + Number(g.current_amount),
    0
  );

  const totalTarget = active.reduce(
    (sum, g) => sum + Number(g.target_amount),
    0
  );

  const overallProgress =
    totalTarget === 0
      ? 0
      : Math.min(
          100,
          Math.round(
            (active.reduce((s, g) => s + Number(g.current_amount), 0) /
              totalTarget) *
              100
          )
        );

  return (
    <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-4 mb-8">
      <StatCard
        title="Active Goals"
        value={active.length}
        color="bg-blue-100 text-blue-600"
        icon={<Target size={24} />}
      />

      <StatCard
        title="Completed"
        value={completed.length}
        color="bg-green-100 text-green-600"
        icon={<CheckCircle size={24} />}
      />

      <StatCard
        title="Total Saved"
        value={formatCurrency(totalSaved)}
        color="bg-emerald-100 text-emerald-600"
        icon={<IndianRupee size={24} />}
      />

      <StatCard
        title="Overall Progress"
        value={`${overallProgress}%`}
        color={
          overallProgress >= 75
            ? "bg-green-100 text-green-600"
            : overallProgress >= 50
            ? "bg-yellow-100 text-yellow-600"
            : "bg-blue-100 text-blue-600"
        }
        icon={<TrendingUp size={24} />}
      />
    </div>
  );
}
