import {
  ArrowDownRight,
  ArrowUpRight,
  PiggyBank,
  TrendingDown,
  TrendingUp,
  Wallet,
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
  trend,
  positive = true,
  icon: Icon,
  gradient,
}) {
  return (
    <div className="group relative overflow-hidden rounded-[28px] border border-slate-200/70 bg-white p-6 shadow-sm transition-all duration-300 hover:-translate-y-1 hover:shadow-xl">
      {/* Background Glow */}
      <div
        className={`absolute inset-0 opacity-0 transition-opacity duration-300 group-hover:opacity-100 ${gradient}`}
      />

      <div className="relative z-10">
        <div className="flex items-start justify-between">
          <div>
            <p className="text-sm font-medium text-slate-500">
              {title}
            </p>

            <h2 className="mt-3 text-3xl font-bold tracking-tight text-slate-900">
              {value}
            </h2>
          </div>

          <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-slate-100 transition-all duration-300 group-hover:scale-110">
            <Icon
              size={28}
              className="text-slate-700"
            />
          </div>
        </div>

        <div className="mt-8 flex items-center justify-between border-t border-slate-100 pt-5">
          <span className="text-sm text-slate-500">
            {subtitle}
          </span>

          <div
            className={`flex items-center gap-1 rounded-full px-3 py-1 text-sm font-semibold ${
              positive
                ? "bg-emerald-50 text-emerald-600"
                : "bg-red-50 text-red-600"
            }`}
          >
            {positive ? (
              <ArrowUpRight size={15} />
            ) : (
              <ArrowDownRight size={15} />
            )}

            {trend}
          </div>
        </div>
      </div>
    </div>
  );
}

export default function StatsCards({
  balance,
  income,
  expenses,
  savings,
}) {
  const savingsRate =
    income > 0
      ? Math.round((savings / income) * 100)
      : 0;

  const budgetUsed =
    income > 0
      ? Math.round((Math.abs(expenses) / income) * 100)
      : 0;

  const cards = [
    {
      title: "Available Balance",
      value: formatCurrency(balance),
      subtitle: "Current available funds",
      trend: "+8.2%",
      positive: true,
      icon: Wallet,
      gradient:
        "bg-gradient-to-br from-blue-50 via-transparent to-blue-100",
    },
    {
      title: "Monthly Income",
      value: formatCurrency(income),
      subtitle: "Money received this month",
      trend: "+12%",
      positive: true,
      icon: TrendingUp,
      gradient:
        "bg-gradient-to-br from-emerald-50 via-transparent to-emerald-100",
    },
    {
      title: "Monthly Expenses",
      value: formatCurrency(Math.abs(expenses)),
      subtitle: `${budgetUsed}% of income spent`,
      trend: "-5%",
      positive: false,
      icon: TrendingDown,
      gradient:
        "bg-gradient-to-br from-red-50 via-transparent to-red-100",
    },
    {
      title: "Savings Rate",
      value: `${savingsRate}%`,
      subtitle: formatCurrency(savings),
      trend: "Healthy",
      positive: true,
      icon: PiggyBank,
      gradient:
        "bg-gradient-to-br from-violet-50 via-transparent to-violet-100",
    },
  ];

  return (
    <section className="mt-8">
      <div className="mb-5 flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-slate-900">
            Financial Health
          </h2>

          <p className="mt-1 text-sm text-slate-500">
            A quick snapshot of your financial performance this month.
          </p>
        </div>

        <div className="rounded-full bg-blue-50 px-4 py-2 text-sm font-semibold text-blue-600">
          Updated Live
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-4">
        {cards.map((card) => (
          <StatCard
            key={card.title}
            {...card}
          />
        ))}
      </div>
    </section>
  );
}