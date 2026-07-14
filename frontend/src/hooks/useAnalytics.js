import { useCallback, useEffect, useState } from "react";

import {
  getOverview,
  getExpenseByCategory,
  getMonthlyTrend,
  getSavingsTrend,
} from "../services/analyticsService";

export default function useAnalytics() {
  const [overview, setOverview] = useState(null);
  const [expenseCategories, setExpenseCategories] = useState([]);
  const [monthlyTrend, setMonthlyTrend] = useState([]);
  const [savingsTrend, setSavingsTrend] = useState([]);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadAnalytics = useCallback(async () => {
    setLoading(true);
    setError("");

    try {
      const [
        overviewData,
        categoryData,
        monthlyData,
        savingsData,
      ] = await Promise.all([
        getOverview(),
        getExpenseByCategory(),
        getMonthlyTrend(),
        getSavingsTrend(),
      ]);

      setOverview(overviewData);
      setExpenseCategories(categoryData);
      setMonthlyTrend(monthlyData);
      setSavingsTrend(savingsData);
    } catch (err) {
      console.error(err);

      setError("Failed to load analytics.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAnalytics();
  }, [loadAnalytics]);

  return {
    overview,
    expenseCategories,
    monthlyTrend,
    savingsTrend,

    loading,
    error,

    refresh: loadAnalytics,
  };
}