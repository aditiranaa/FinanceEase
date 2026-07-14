import { useState } from "react";

import AppLayout from "../../components/layout/AppLayout";

import useAnalytics from "../../hooks/useAnalytics";

import AnalyticsHeader from "../../components/analytics/AnalyticsHeader";
import AnalyticsOverview from "../../components/analytics/AnalyticsOverview";
import AnalyticsGrid from "../../components/analytics/AnalyticsGrid";
import AnalyticsSkeleton from "../../components/analytics/AnalyticsSkeleton";
import EmptyAnalytics from "../../components/analytics/EmptyAnalytics";

export default function Analytics() {
  const {
    overview,
    expenseCategories,
    monthlyTrend,
    loading,
    error,
  } = useAnalytics();

  const [period, setPeriod] = useState("all");

  return (
    <AppLayout>
      {loading ? (
        <AnalyticsSkeleton />
      ) : error ? (
        <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-center text-red-600">
          {error}
        </div>
      ) : !overview ? (
        <EmptyAnalytics />
      ) : (
        <div className="mx-auto max-w-[1320px] space-y-4">
          <AnalyticsHeader />

          <AnalyticsOverview
            overview={overview}
          />

          <AnalyticsGrid
            incomeExpenseData={monthlyTrend}
            categoryData={expenseCategories}
            monthlyData={monthlyTrend}
          />

          
        </div>
      )}
    </AppLayout>
  );
}