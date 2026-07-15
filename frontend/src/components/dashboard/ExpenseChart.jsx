import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

const COLORS = [
  "#10B981",
  "#3B82F6",
  "#F59E0B",
  "#EF4444",
  "#8B5CF6",
  "#06B6D4",
  "#EC4899",
];

export default function ExpenseChart({
  transactions,
}) {
  // Group expenses by category
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
  ).map(([name, value]) => ({
    name,
    value,
  }));

  const totalExpenses =
    expenseData.reduce(
      (sum, item) => sum + item.value,
      0
    );

  return (
    <section className="rounded-3xl border border-gray-200 bg-white p-7 shadow-sm">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">
            Expense Breakdown
          </h2>

          <p className="mt-1 text-sm text-gray-500">
            Spending by category
          </p>
        </div>

        <div className="rounded-2xl bg-gray-50 px-5 py-3">
          <p className="text-xs uppercase tracking-wide text-gray-500">
            Total Spent
          </p>

          <p className="mt-1 text-xl font-bold text-gray-900">
            ₹
            {totalExpenses.toLocaleString(
              "en-IN"
            )}
          </p>
        </div>
      </div>

      {expenseData.length === 0 ? (
        <div className="flex h-80 items-center justify-center rounded-2xl border border-dashed border-gray-200 bg-gray-50">
          <p className="text-gray-500">
            No expense data available.
          </p>
        </div>
      ) : (
        <div className="h-96">
          <ResponsiveContainer
            width="100%"
            height="100%"
          >
            <PieChart>
              <Pie
                data={expenseData}
                dataKey="value"
                nameKey="name"
                innerRadius={80}
                outerRadius={130}
                paddingAngle={3}
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
                  `₹${Number(
                    value
                  ).toLocaleString(
                    "en-IN"
                  )}`,
                  "Spent",
                ]}
              />

              <Legend
                verticalAlign="bottom"
                iconType="circle"
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      )}
    </section>
  );
}