import Navbar from "../../components/layout/Navbar";
import Sidebar from "../../components/layout/Sidebar";

import useGoals from "../../hooks/useGoals";

import GoalOverview from "../../components/goals/GoalOverview";
import GoalAlerts from "../../components/goals/GoalAlerts";
import GoalManager from "./GoalManager";

import { useState } from "react";
import GoalToolbar from "../../components/goals/GoalToolbar";

import GoalHeader from "../../components/goals/GoalHeader";

import GoalSkeleton from "../../components/goals/GoalSkeleton";

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

const [search, setSearch] = useState("");
const [category, setCategory] = useState("all");
const [status, setStatus] = useState("all");
const [sort, setSort] = useState("deadline");
const [showForm, setShowForm] = useState(false);
  return (
    <div className="flex flex-col md:flex-row">
      <Sidebar />

      <div className="flex-1 p-6 bg-gray-100 dark:bg-gray-950 min-h-screen">
        <Navbar />

        <div className="mt-8 space-y-8">
          <GoalHeader
            onAdd={() => setShowForm(true)}
          />

          {loading && (
            <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-3">
              {Array.from({ length: 6 }).map((_, index) => (
                <GoalSkeleton key={index} />
              ))}
            </div>
          )}

          {error && (
            <div className="text-center text-red-600 py-10">{error}</div>
          )}

          {!loading && !error && (
            <>
              <GoalOverview goals={goals} />

            <GoalAlerts goals={goals} />

            <GoalToolbar
              search={search}
              setSearch={setSearch}
              category={category}
              setCategory={setCategory}
              status={status}
              setStatus={setStatus}
              sort={sort}
              setSort={setSort}
              onAdd={() => setShowForm(true)}
            />

            <GoalManager
              goals={goals}
              addGoal={addGoal}
              editGoal={editGoal}
              removeGoal={removeGoal}
              completeGoal={completeGoal}
              showForm={showForm}
              setShowForm={setShowForm}
              search={search}
              category={category}
              status={status}
              sort={sort}
            />
            </>
          )}
        </div>
      </div>
    </div>
  );
}
