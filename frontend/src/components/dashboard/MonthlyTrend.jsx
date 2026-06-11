import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";

const MonthlyTrendChart = ({
  transactions,
}) => {

  const monthlyData = {};

  transactions.forEach(
    (transaction) => {

      const month =
        new Date(
          transaction.date
        ).toLocaleString(
          "default",
          {
            month: "short",
          }
        );

      if (!monthlyData[month]) {

        monthlyData[month] = 0;

      }

      monthlyData[month] +=
        Math.abs(
          Number(
            transaction.amount
          )
        );

    }
  );

  const chartData =
    Object.entries(
      monthlyData
    ).map(
      ([month, total]) => ({
        month,
        total,
      })
    );

  return (

    <div
      className="
        bg-white
        rounded-2xl
        p-6
        shadow-sm
        mt-8
      "
    >

      <h2
        className="
          text-2xl
          font-bold
          mb-6
        "
      >
        Monthly Spending Trend
      </h2>

      <ResponsiveContainer
        width="100%"
        height={300}
      >

        <LineChart
          data={chartData}
        >

          <CartesianGrid
            strokeDasharray="3 3"
          />

          <XAxis
            dataKey="month"
          />

          <YAxis />

          <Tooltip />

          <Line
            type="monotone"
            dataKey="total"
            stroke="#3B82F6"
          />

        </LineChart>

      </ResponsiveContainer>

    </div>

  );

};

export default MonthlyTrendChart;