import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  CartesianGrid,
  ResponsiveContainer,
} from "recharts";

export default function IncomeExpenseChart({
  data,
}) {
  return (
    <div className="bg-white dark:bg-gray-900 rounded-xl shadow p-6">

      <h2 className="text-xl font-bold mb-5">
        Income vs Expense
      </h2>

      <ResponsiveContainer
        width="100%"
        height={350}
      >
        <BarChart data={data}>

          <CartesianGrid strokeDasharray="3 3" />

          <XAxis dataKey="month" />

          <YAxis />

          <Tooltip />

          <Legend />

          <Bar
            dataKey="income"
            fill="#16a34a"
          />

          <Bar
            dataKey="expense"
            fill="#dc2626"
          />

        </BarChart>
      </ResponsiveContainer>

    </div>
  );
}