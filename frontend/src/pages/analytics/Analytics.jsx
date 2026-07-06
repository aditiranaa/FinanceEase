import Navbar from "../../components/layout/Navbar";
import Sidebar from "../../components/layout/Sidebar";

import useAnalytics from "../../hooks/useAnalytics";

import AnalyticsDashboard from "./AnalyticsDashboard";

export default function Analytics() {

  const {
    overview,
    expenseCategories,
    monthlyTrend,
    savingsTrend,
    loading,
    error,
  } = useAnalytics();

  if (loading) {
    return (
      <div className="flex justify-center items-center h-screen">
        <p className="text-lg">
          Loading analytics...
        </p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex justify-center items-center h-screen text-red-600">
        {error}
      </div>
    );
  }

  return (
    <div className="flex flex-col md:flex-row">

      <Sidebar />

      <div className="flex-1 p-6 bg-gray-100 dark:bg-gray-950 min-h-screen">

        <Navbar />

        <div className="mt-8 space-y-8">

          <div>

            <h1 className="text-3xl font-bold">
              Financial Analytics
            </h1>

            <p className="text-gray-500">
              Track your income, expenses,
              savings and financial trends.
            </p>

          </div>

          <AnalyticsDashboard
            overview={overview}
            expenseCategories={expenseCategories}
            monthlyTrend={monthlyTrend}
            savingsTrend={savingsTrend}
          />

        </div>

      </div>

    </div>
  );
}