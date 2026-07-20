import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
} from "recharts";

import {
  TrendingDown,
  ArrowRight,
} from "lucide-react";

const COLORS = [
  "#2563EB",
  "#38BDF8",
  "#14B8A6",
  "#8B5CF6",
  "#F59E0B",
  "#F97316",
  "#EF4444",
];

const formatCurrency = (value) =>
  Number(value || 0).toLocaleString("en-IN", {
    style: "currency",
    currency: "INR",
    maximumFractionDigits: 0,
  });

export default function ExpenseChart({
  transactions,
}) {
  const groupedExpenses = transactions
    .filter(
      (transaction) =>
        Number(transaction.amount) < 0
    )
    .reduce((acc, transaction) => {
      const category =
        transaction.category || "Other";

      acc[category] =
        (acc[category] || 0) +
        Math.abs(Number(transaction.amount));

      return acc;
    }, {});

  const expenseData = Object.entries(
    groupedExpenses
  )
    .map(([name, value]) => ({
      name,
      value,
    }))
    .sort((a, b) => b.value - a.value);

  const totalExpenses =
    expenseData.reduce(
      (sum, item) => sum + item.value,
      0
    );

  const topCategories =
    expenseData.slice(0, 5);

  return (
    <section className="overflow-hidden rounded-[32px] border border-slate-200 bg-white shadow-sm">

      {/* Header */}

      <div className="border-b border-slate-100 p-8">

        <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">

          <div>

            <div className="inline-flex items-center gap-2 rounded-full bg-red-50 px-4 py-2 text-sm font-semibold text-red-600">
              <TrendingDown size={16} />
              Monthly Spending
            </div>

            <h2 className="mt-5 text-3xl font-bold tracking-tight text-slate-900">
              Expense Breakdown
            </h2>

            <p className="mt-2 text-slate-500">
              See exactly where your money is
              going this month.
            </p>

          </div>

          <div className="rounded-3xl bg-slate-50 px-7 py-5 text-right">

            <p className="text-xs font-semibold uppercase tracking-[0.25em] text-slate-500">
              Total Spent
            </p>

            <h3 className="mt-2 text-3xl font-bold text-slate-900">
              {formatCurrency(totalExpenses)}
            </h3>

          </div>

        </div>

      </div>

      {expenseData.length === 0 ? (

        <div className="flex h-[430px] items-center justify-center">

          <div className="text-center">

            <div className="mx-auto flex h-20 w-20 items-center justify-center rounded-full bg-slate-100">

              <TrendingDown
                size={34}
                className="text-slate-400"
              />

            </div>

            <h3 className="mt-6 text-2xl font-bold text-slate-800">
              No Expenses Yet
            </h3>

            <p className="mt-2 text-slate-500">
              Once you add transactions,
              your spending breakdown will
              appear here.
            </p>

          </div>

        </div>

      ) : (

        <div className="grid gap-10 p-8 lg:grid-cols-[1.2fr_.8fr]">

          {/* Chart */}

          <div className="relative h-[420px]">

            <ResponsiveContainer
              width="100%"
              height="100%"
            >

              <PieChart>

                <Pie
                  data={expenseData}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={95}
                  outerRadius={145}
                  paddingAngle={4}
                  stroke="none"
                >

                  {expenseData.map(
                    (_, index) => (
                      <Cell
                        key={index}
                        fill={
                          COLORS[
                            index %
                              COLORS.length
                          ]
                        }
                      />
                    )
                  )}

                </Pie>

                <Tooltip
                  formatter={(value) => [
                    formatCurrency(value),
                    "Spent",
                  ]}
                  contentStyle={{
                    borderRadius: 16,
                    border: "none",
                    boxShadow:
                      "0 12px 35px rgba(15,23,42,.12)",
                  }}
                />

              </PieChart>

            </ResponsiveContainer>

            {/* Center Label */}

            <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">

              <p className="text-sm font-medium text-slate-500">
                Total Spending
              </p>

              <h3 className="mt-2 text-4xl font-black text-slate-900">
                {formatCurrency(totalExpenses)}
              </h3>

              <p className="mt-2 rounded-full bg-red-50 px-4 py-1 text-sm font-semibold text-red-600">
                This Month
              </p>

            </div>

          </div>

          {/* Category Panel */}

          <div className="flex flex-col">
                        <h3 className="text-xl font-bold text-slate-900">
              Top Categories
            </h3>

            <p className="mt-2 text-sm text-slate-500">
              Your highest spending categories this month.
            </p>

            <div className="mt-8 space-y-4">
              {topCategories.map((item, index) => {
                const percentage =
                  totalExpenses > 0
                    ? (
                        (item.value / totalExpenses) *
                        100
                      ).toFixed(1)
                    : 0;

                return (
                  <div
                    key={item.name}
                    className="group rounded-2xl border border-slate-200 bg-white p-5 transition-all duration-300 hover:-translate-y-1 hover:border-blue-200 hover:shadow-lg"
                  >
                    <div className="flex items-center justify-between">

                      <div className="flex items-center gap-4">

                        <div
                          className="h-4 w-4 rounded-full"
                          style={{
                            backgroundColor:
                              COLORS[index % COLORS.length],
                          }}
                        />

                        <div>
                          <h4 className="font-semibold text-slate-900">
                            {item.name}
                          </h4>

                          <p className="text-sm text-slate-500">
                            {percentage}% of spending
                          </p>
                        </div>

                      </div>

                      <div className="text-right">

                        <h4 className="font-bold text-slate-900">
                          {formatCurrency(item.value)}
                        </h4>

                      </div>

                    </div>

                    <div className="mt-4 h-2 overflow-hidden rounded-full bg-slate-100">

                      <div
                        className="h-full rounded-full transition-all duration-700"
                        style={{
                          width: `${percentage}%`,
                          backgroundColor:
                            COLORS[index % COLORS.length],
                        }}
                      />

                    </div>

                  </div>
                );
              })}
            </div>

            <button
              className="
                mt-8
                inline-flex
                w-fit
                items-center
                gap-2
                rounded-2xl
                bg-blue-600
                px-6
                py-3
                font-semibold
                text-white
                transition-all
                duration-300
                hover:-translate-y-1
                hover:bg-blue-700
                hover:shadow-xl
              "
            >
              View Analytics

              <ArrowRight size={18} />
            </button>

          </div>

        </div>

      )}

    </section>
  );
}