import Navbar from "../../components/layout/Navbar";
import Sidebar from "../../components/layout/Sidebar";

import useGoals from "../../hooks/useGoals";

import GoalOverview from "../../components/goals/GoalOverview";
import GoalAlerts from "../../components/goals/GoalAlerts";
import GoalManager from "./GoalManager";

export default function Goals() {
  const {
    goals,
    loading,
    error,
    addGoal,
    editGoal,
    removeGoal,
    completeGoal,
  } = useGoals();

  return (
    <div className="flex flex-col md:flex-row">
      <Sidebar />

      <div className="flex-1 p-6 bg-gray-100 dark:bg-gray-950 min-h-screen">
        <Navbar />

        <div className="mt-8 space-y-8">
          <div>
            <h1 className="text-3xl font-bold">Savings Goals</h1>
            <p className="text-gray-500">
              Set targets, track progress, and celebrate milestones.
            </p>
          </div>

          {loading && (
            <div className="flex justify-center items-center h-60">
              <p className="text-lg">Loading goals...</p>
            </div>
          )}

          {error && (
            <div className="text-center text-red-600 py-10">{error}</div>
          )}

          {!loading && !error && (
            <>
              <GoalOverview goals={goals} />
              <GoalAlerts goals={goals} />
              <GoalManager
                goals={goals}
                addGoal={addGoal}
                editGoal={editGoal}
                removeGoal={removeGoal}
                completeGoal={completeGoal}
              />
            </>
          )}
        </div>
      </div>
    </div>
  );
}
