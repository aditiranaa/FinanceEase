import { useEffect, useState } from "react";

import {
  getGoals,
  createGoal,
  updateGoal,
  deleteGoal,
  markGoalComplete,
} from "../services/goalService";

import toast from "react-hot-toast";



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
    toast.success("Goal created!");
    loadGoals();
  };

  const editGoal = async (id, goal) => {
    await updateGoal(id, goal);
    toast.success("Goal updated!");
    loadGoals();
  };

  const removeGoal = async (id) => {
    await deleteGoal(id);
    toat.success("Goal Deleted!")
    loadGoals();
  };

  const completeGoal = async (id) => {
    await markGoalComplete(id);
    toast.success("Congratulations! 🎉");
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