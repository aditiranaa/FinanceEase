import IncomeExpenseChart from "./IncomeExpenseChart";
import ExpenseBreakdown from "./ExpenseBreakdown";
import MonthlyTrend from "./MonthlyTrend";

export default function AnalyticsGrid({
  incomeExpenseData,
  categoryData,
  monthlyData,
}) {
  return (
    <div className="space-y-5">
      {/* Hero Chart */}
      <IncomeExpenseChart
        data={incomeExpenseData}
      />

      {/* Bottom Charts */}
      <div className="grid gap-5 lg:grid-cols-2">
        <ExpenseBreakdown
          data={categoryData}
        />

        <MonthlyTrend
          data={monthlyData}
        />
      </div>
    </div>
  );
}