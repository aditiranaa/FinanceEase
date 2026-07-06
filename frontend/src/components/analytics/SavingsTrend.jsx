import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ResponsiveContainer,
} from "recharts";

export default function SavingsTrend({ data }) {
  return (
    <div className="bg-white dark:bg-gray-900 rounded-xl shadow p-6">

      <h2 className="text-xl font-bold mb-5">
        Savings Progress
      </h2>

      <ResponsiveContainer width="100%" height={350}>
        <LineChart data={data}>

          <CartesianGrid strokeDasharray="3 3" />

          <XAxis dataKey="title" />

          <YAxis />

          <Tooltip />

          <Line
            type="monotone"
            dataKey="saved"
            stroke="#16a34a"
            strokeWidth={3}
          />

          <Line
            type="monotone"
            dataKey="target"
            stroke="#2563eb"
            strokeDasharray="5 5"
            strokeWidth={2}
          />

        </LineChart>
      </ResponsiveContainer>

    </div>
  );
}