import {
  Wallet,
  TrendingDown,
  PiggyBank,
  Target,
} from "lucide-react";

const formatCurrency = (value) =>
  Number(value || 0).toLocaleString("en-IN", {
    style: "currency",
    currency: "INR",
    maximumFractionDigits: 0,
  });

const Card = ({ title, value, icon, color }) => (
  <div className="bg-white dark:bg-gray-900 rounded-xl shadow-md border border-gray-200 dark:border-gray-800 p-5">
    <div className="flex items-center justify-between">
      <div>
        <p className="text-sm text-gray-500">{title}</p>
        <h2 className="mt-2 text-2xl font-bold">{value}</h2>
      </div>

      <div
        className={`w-12 h-12 rounded-full flex items-center justify-center ${color}`}
      >
        {icon}
      </div>
    </div>
  </div>
);

export default function AnalyticsOverview({ overview }) {
  if (!overview) return null;

  return (
    <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-4">

      <Card
        title="Income"
        value={formatCurrency(overview.totalIncome)}
        color="bg-green-100 text-green-600"
        icon={<Wallet size={24} />}
      />

      <Card
        title="Expenses"
        value={formatCurrency(overview.totalExpense)}
        color="bg-red-100 text-red-600"
        icon={<TrendingDown size={24} />}
      />

      <Card
        title="Savings"
        value={formatCurrency(overview.savings)}
        color="bg-blue-100 text-blue-600"
        icon={<PiggyBank size={24} />}
      />

      <Card
        title="Goals Completed"
        value={`${overview.completedGoals}/${overview.totalGoals}`}
        color="bg-purple-100 text-purple-600"
        icon={<Target size={24} />}
      />

    </div>
  );
}