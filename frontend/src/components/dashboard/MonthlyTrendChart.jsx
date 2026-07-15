import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from "recharts";

const MONTHS = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];

export default function MonthlyTrendChart({
  transactions,
}) {
  const monthlyData = {};

  transactions.forEach((transaction) => {
    const month = new Date(
      transaction.date
    ).toLocaleString("default", {
      month: "short",
    });

    if (!monthlyData[month]) {
      monthlyData[month] = {
        income: 0,
        expenses: 0,
      };
    }

    const amount = Number(transaction.amount);

    if (amount >= 0) {
      monthlyData[month].income += amount;
    } else {
      monthlyData[month].expenses += Math.abs(amount);
    }
  });

  const chartData = MONTHS.filter(
    (month) => monthlyData[month]
  ).map((month) => ({
    month,
    income: monthlyData[month].income,
    expenses: monthlyData[month].expenses,
  }));

  return (
    <section className="rounded-3xl border border-gray-200 bg-white p-7 shadow-sm">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">
            Monthly Cash Flow
          </h2>

          <p className="mt-1 text-sm text-gray-500">
            Income versus expenses over time.
          </p>
        </div>
      </div>

      {chartData.length === 0 ? (
        <div className="flex h-80 items-center justify-center rounded-2xl border border-dashed border-gray-200 bg-gray-50">
          <p className="text-gray-500">
            No monthly data available.
          </p>
        </div>
      ) : (
        <ResponsiveContainer
          width="100%"
          height={360}
        >
          <AreaChart data={chartData}>
            <defs>
              <linearGradient
                id="incomeFill"
                x1="0"
                y1="0"
                x2="0"
                y2="1"
              >
                <stop
                  offset="5%"
                  stopColor="#10B981"
                  stopOpacity={0.35}
                />
                <stop
                  offset="95%"
                  stopColor="#10B981"
                  stopOpacity={0}
                />
              </linearGradient>

              <linearGradient
                id="expenseFill"
                x1="0"
                y1="0"
                x2="0"
                y2="1"
              >
                <stop
                  offset="5%"
                  stopColor="#EF4444"
                  stopOpacity={0.28}
                />
                <stop
                  offset="95%"
                  stopColor="#EF4444"
                  stopOpacity={0}
                />
              </linearGradient>
            </defs>

            <CartesianGrid
              strokeDasharray="4 4"
              vertical={false}
              stroke="#E5E7EB"
            />

            <XAxis
              dataKey="month"
              tickLine={false}
              axisLine={false}
            />

            <YAxis
              tickLine={false}
              axisLine={false}
            />

            <Tooltip
              formatter={(value) => [
                `₹${Number(value).toLocaleString(
                  "en-IN"
                )}`,
              ]}
            />

            <Area
              type="monotone"
              dataKey="income"
              name="Income"
              stroke="#10B981"
              strokeWidth={3}
              fill="url(#incomeFill)"
            />

            <Area
              type="monotone"
              dataKey="expenses"
              name="Expenses"
              stroke="#EF4444"
              strokeWidth={3}
              fill="url(#expenseFill)"
            />
          </AreaChart>
        </ResponsiveContainer>
      )}
    </section>
  );
}