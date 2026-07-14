import {
  ResponsiveContainer,
  LineChart,
  Line,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
} from "recharts";

const formatCurrency = (value) =>
  Number(value || 0).toLocaleString("en-IN", {
    style: "currency",
    currency: "INR",
    maximumFractionDigits: 0,
  });

export default function IncomeExpenseChart({
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
        p-4
        shadow-sm
      "
    >
      <div className="mb-3">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
          Income vs Expenses
        </h2>

        <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
          Monthly comparison
        </p>
      </div>

      <div className="h-[210px]">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart
            data={data}
            margin={{
              top: 10,
              right: 15,
              left: -15,
              bottom: 0,
            }}
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
              tick={{ fontSize: 12 }}
            />

            <YAxis
              tickLine={false}
              axisLine={false}
              tick={{ fontSize: 12 }}
              tickFormatter={(value) =>
                `₹${(value / 1000).toFixed(0)}K`
              }
            />

            <Tooltip
              formatter={(value) =>
                formatCurrency(value)
              }
            />

            <Legend
              verticalAlign="top"
              align="right"
              iconType="circle"
              wrapperStyle={{
                paddingBottom: 12,
              }}
            />

            <Line
              type="natural"
              dataKey="income"
              name="Income"
              stroke="#2563eb"
              strokeWidth={3}
              dot={false}
              activeDot={{ r: 5 }}
            />

            <Line
              type="natural"
              dataKey="expense"
              name="Expenses"
              stroke="#ef4444"
              strokeWidth={3}
              dot={false}
              activeDot={{ r: 5 }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}