import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

const COLORS = [
  "#16a34a",
  "#2563eb",
  "#dc2626",
  "#d97706",
  "#7c3aed",
  "#0f766e",
  "#db2777",
];

export default function ExpenseByCategory({ data }) {
  return (
    <div className="bg-white dark:bg-gray-900 rounded-xl shadow p-6">

      <h2 className="text-xl font-bold mb-5">
        Expenses by Category
      </h2>

      <ResponsiveContainer
        width="100%"
        height={320}
      >
        <PieChart>

          <Pie
            data={data}
            dataKey="amount"
            nameKey="category"
            outerRadius={110}
            label
          >
            {data.map((entry, index) => (
              <Cell
                key={index}
                fill={
                  COLORS[
                    index % COLORS.length
                  ]
                }
              />
            ))}
          </Pie>

          <Tooltip />

          <Legend />

        </PieChart>
      </ResponsiveContainer>

    </div>
  );
}