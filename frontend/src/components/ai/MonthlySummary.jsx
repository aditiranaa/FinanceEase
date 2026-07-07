import {
  Wallet,
  TrendingDown,
  PiggyBank,
} from "lucide-react";

const Card = ({
  title,
  value,
  icon,
  color,
}) => (
  <div className="bg-white dark:bg-gray-900 rounded-xl shadow p-5">

    <div className="flex items-center justify-between">

      <div>

        <p className="text-gray-500 text-sm">
          {title}
        </p>

        <h2 className="text-2xl font-bold mt-2">
          ₹{Number(value).toLocaleString()}
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

export default function MonthlySummary({
  overview,
}) {

  if (!overview) return null;

  return (
    <div className="grid gap-5 md:grid-cols-3">

      <Card
        title="Income"
        value={overview.totalIncome}
        color="bg-green-100 text-green-600"
        icon={<Wallet />}
      />

      <Card
        title="Expenses"
        value={overview.totalExpense}
        color="bg-red-100 text-red-600"
        icon={<TrendingDown />}
      />

      <Card
        title="Savings"
        value={overview.savings}
        color="bg-blue-100 text-blue-600"
        icon={<PiggyBank />}
      />

    </div>
  );
}