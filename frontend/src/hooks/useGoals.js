import { useEffect, useState } from "react";

import {
  getGoals,
  createGoal,
  updateGoal,
  deleteGoal,
  markGoalComplete,
} from "../services/goalService";

export default function useGoals() {
  const [goals, setGoals] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadGoals = async () => {
    try {
      setLoading(true);
      const data = await getGoals();
      setGoals(data);
      setError(null);
    } catch (err) {
      setError(
        err.response?.data?.message || "Failed to load goals."
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadGoals();
  }, []);

  const addGoal = async (goal) => {
    await createGoal(goal);
    loadGoals();
  };

  const editGoal = async (id, goal) => {
    await updateGoal(id, goal);
    loadGoals();
  };

  const removeGoal = async (id) => {
    await deleteGoal(id);
    loadGoals();
  };

  const completeGoal = async (id) => {
    await markGoalComplete(id);
    loadGoals();
  };

  return {
    goals,
    loading,
    error,
    addGoal,
    editGoal,
    removeGoal,
    completeGoal,
    refresh: loadGoals,
  };
}