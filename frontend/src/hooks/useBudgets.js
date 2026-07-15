import { useState, useEffect, useCallback } from "react";
import {
  getBudgets,
  createBudget,
  updateBudget,
  deleteBudget,
} from "../services/budgetService";

export default function useBudgets() {
  const [budgets, setBudgets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchBudgets = useCallback(async () => {
    try {
      setLoading(true);

      const data = await getBudgets();

      setBudgets(data);
      setError(null);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchBudgets();
  }, [fetchBudgets]);

  const addBudget = useCallback(async (data) => {
    const created = await createBudget(data);

    setBudgets((prev) => [...prev, created]);

    return created;
  }, []);

  const editBudget = useCallback(async (id, data) => {
    const updated = await updateBudget(id, data);

    setBudgets((prev) =>
      prev.map((budget) =>
        budget.id === id ? updated : budget
      )
    );

    return updated;
  }, []);

  const removeBudget = useCallback(async (id) => {
    await deleteBudget(id);

    setBudgets((prev) =>
      prev.filter((budget) => budget.id !== id)
    );
  }, []);

  return {
    budgets,
    loading,
    error,
    addBudget,
    editBudget,
    removeBudget,
    refetch: fetchBudgets,
  };
}