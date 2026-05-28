import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

const ExpenseChart = ({
  transactions,
}) => {

  const expenseData =
    transactions
      .filter(
        (transaction) =>
          transaction.amount < 0
      )
      .map((transaction) => ({
        name:
          transaction.category,

        value:
          Math.abs(
            Number(
              transaction.amount
            )
          ),
      }));

  const COLORS = [
    "#ef4444",
    "#3b82f6",
    "#22c55e",
    "#f59e0b",
    "#8b5cf6",
  ];

  return (

    <div
      className="
        mt-8
        bg-white
        rounded-2xl
        shadow-sm
        p-6
      "
    >

      <h2
        className="
          text-2xl
          font-bold
          mb-6
          text-gray-800
        "
      >
        Expense Breakdown
      </h2>

      <div className="h-80">

        <ResponsiveContainer>

          <PieChart>

            <Pie
              data={expenseData}
              dataKey="value"
              nameKey="name"
              outerRadius={120}
            >

              {expenseData.map(
                (entry, index) => (

                <Cell
                  key={index}

                  fill={
                    COLORS[
                      index %
                      COLORS.length
                    ]
                  }
                />
              ))}

            </Pie>

            <Tooltip />

          </PieChart>

        </ResponsiveContainer>

      </div>

    </div>
  );
};

export default ExpenseChart;