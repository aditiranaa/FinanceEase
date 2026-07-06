import AnalyticsOverview from "../../components/analytics/AnalyticsOverview";
import ExpenseByCategory from "../../components/analytics/ExpenseByCategory";
import IncomeExpenseChart from "../../components/analytics/IncomeExpenseChart";
import MonthlyTrend from "../../components/analytics/MonthlyTrend";
import SavingsTrend from "../../components/analytics/SavingsTrend";
import AnalyticsFilters from "../../components/analytics/AnalyticsFilters";

export default function AnalyticsDashboard({
  overview,
  expenseCategories,
  monthlyTrend,
  savingsTrend,
}) {
  return (
    <div className="space-y-8">

      <AnalyticsFilters />

      <AnalyticsOverview
        overview={overview}
      />

      <div className="grid gap-6 xl:grid-cols-2">

        <ExpenseByCategory
          data={expenseCategories}
        />

        <IncomeExpenseChart
          data={monthlyTrend}
        />

      </div>

      <div className="grid gap-6 xl:grid-cols-2">

        <MonthlyTrend
          data={monthlyTrend}
        />

        <SavingsTrend
          data={savingsTrend}
        />

      </div>

    </div>
  );
}