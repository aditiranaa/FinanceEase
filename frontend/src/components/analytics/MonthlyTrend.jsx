import {
  ResponsiveContainer,
  BarChart,
  Bar,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
} from "recharts";

const formatCurrency = (value) =>
  Number(value || 0).toLocaleString("en-IN", {
    style: "currency",
    currency: "INR",
    maximumFractionDigits: 0,
  });

export default function MonthlyTrend({
  data = [],
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
      "
    >
      <div className="mb-4">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
          Monthly Spending
        </h2>

        <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
          Monthly expense overview
        </p>
      </div>

      <div className="h-[210px]">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={data}
            margin={{
              top: 10,
              right: 10,
              left: -15,
              bottom: 0,
            }}
            barCategoryGap="35%"
          >
            <CartesianGrid
              vertical={false}
              strokeDasharray="4 4"
              stroke="#e5e7eb"
            />

            <XAxis
              dataKey="month"
              tickLine={false}
              axisLine={false}
              tick={{
                fontSize: 12,
              }}
            />

            <YAxis
              tickLine={false}
              axisLine={false}
              tick={{
                fontSize: 12,
              }}
              tickFormatter={(value) =>
                `₹${(value / 1000).toFixed(0)}K`
              }
            />

            <Tooltip
              formatter={(value) =>
                formatCurrency(value)
              }
              cursor={{
                fill: "rgba(59,130,246,0.05)",
              }}
            />

            <Bar
              dataKey="expense"
              name="Expenses"
              fill="#3b82f6"
              radius={[6, 6, 0, 0]}
              maxBarSize={42}
            />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}