import {
  Wallet,
  TrendingUp,
  TrendingDown,
  PiggyBank,
  ArrowUpRight,
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
  icon: Icon,
  iconBg,
  iconColor,
  subtitle,
}) {
  return (
    <div className="group rounded-3xl border border-gray-200 bg-white p-6 shadow-sm transition-all duration-300 hover:-translate-y-1 hover:shadow-lg">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm font-medium text-gray-500">
            {title}
          </p>

          <h2 className="mt-4 text-3xl font-bold tracking-tight text-gray-900">
            {value}
          </h2>
        </div>

        <div
          className={`flex h-14 w-14 items-center justify-center rounded-2xl ${iconBg}`}
        >
          <Icon
            size={28}
            className={iconColor}
          />
        </div>
      </div>

      <div className="mt-8 flex items-center justify-between border-t border-gray-100 pt-5">
        <span className="text-sm text-gray-500">
          {subtitle}
        </span>

        <div className="flex items-center gap-1 text-sm font-semibold text-emerald-600">
          <ArrowUpRight size={16} />
          Live
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
  const cards = [
    {
      title: "Total Balance",
      value: formatCurrency(balance),
      icon: Wallet,
      iconBg: "bg-blue-100",
      iconColor: "text-blue-600",
      subtitle: "Current balance",
    },
    {
      title: "Income",
      value: formatCurrency(income),
      icon: TrendingUp,
      iconBg: "bg-emerald-100",
      iconColor: "text-emerald-600",
      subtitle: "Money received",
    },
    {
      title: "Expenses",
      value: formatCurrency(Math.abs(expenses)),
      icon: TrendingDown,
      iconBg: "bg-red-100",
      iconColor: "text-red-600",
      subtitle: "Money spent",
    },
    {
      title: "Savings",
      value: formatCurrency(savings),
      icon: PiggyBank,
      iconBg: "bg-violet-100",
      iconColor: "text-violet-600",
      subtitle: "Available savings",
    },
  ];

  return (
    <section className="grid gap-6 md:grid-cols-2 xl:grid-cols-4">
      {cards.map((card) => (
        <StatCard
          key={card.title}
          title={card.title}
          value={card.value}
          icon={card.icon}
          iconBg={card.iconBg}
          iconColor={card.iconColor}
          subtitle={card.subtitle}
        />
      ))}
    </section>
  );
}