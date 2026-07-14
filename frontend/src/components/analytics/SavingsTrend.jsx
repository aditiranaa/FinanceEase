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

export default function SavingsTrend({
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
        <h2 className="text-lg font-bold text-gray-900 dark:text-white">
          Savings Progress
        </h2>

        <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
          Compare saved amounts against each goal target.
        </p>
      </div>

      <div className="h-[260px]">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data}>
            <CartesianGrid
              strokeDasharray="3 3"
              vertical={false}
              stroke="#e5e7eb"
            />

            <XAxis
              dataKey="title"
              tickLine={false}
              axisLine={false}
            />

            <YAxis
              tickFormatter={(value) =>
                `₹${(value / 1000).toFixed(0)}k`
              }
              tickLine={false}
              axisLine={false}
            />

            <Tooltip
              formatter={(value) =>
                formatCurrency(value)
              }
            />

            <Legend />

            <Line
              type="monotone"
              dataKey="saved"
              name="Saved"
              stroke="#16a34a"
              strokeWidth={3}
              dot={{ r: 4 }}
              activeDot={{ r: 6 }}
            />

            <Line
              type="monotone"
              dataKey="target"
              name="Target"
              stroke="#2563eb"
              strokeWidth={3}
              strokeDasharray="6 6"
              dot={{ r: 3 }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}