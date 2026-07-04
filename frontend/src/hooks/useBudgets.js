import { useEffect, useState } from "react";

import {
  getBudgets,
  createBudget,
  updateBudget,
  deleteBudget,
} from "../services/budgetService";

export default function useBudgets() {
  const [budgets, setBudgets] = useState([]);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState(null);

  const loadBudgets = async () => {
    try {
      setLoading(true);

      const data =
        await getBudgets();

      setBudgets(data);

      setError(null);
    } catch (err) {
      setError(
        err.response?.data?.message ||
          "Failed to load budgets."
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadBudgets();
  }, []);

  const addBudget = async (budget) => {
    await createBudget(budget);
    loadBudgets();
  };

  const editBudget = async (
    id,
    budget
  ) => {
    await updateBudget(id, budget);
    loadBudgets();
  };

  const removeBudget = async (id) => {
    await deleteBudget(id);
    loadBudgets();
  };

  return {
    budgets,
    loading,
    error,
    addBudget,
    editBudget,
    removeBudget,
    refresh: loadBudgets,
  };
}