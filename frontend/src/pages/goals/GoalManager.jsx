import { useState } from "react";

import GoalCard from "../../components/goals/GoalCard";
import GoalForm from "../../components/goals/GoalForm";

export default function GoalManager({
  goals,
  addGoal,
  editGoal,
  removeGoal,
  completeGoal,
}) {
  const [editingGoal, setEditingGoal] = useState(null);
  const [filter, setFilter] = useState("all");

  const handleSubmit = async (goal) => {
    if (editingGoal) {
      await editGoal(editingGoal.id, goal);
      setEditingGoal(null);
    } else {
      await addGoal(goal);
    }
  };

  const filtered = goals.filter((g) => {
    if (filter === "active") return !g.completed;
    if (filter === "completed") return g.completed;
    return true;
  });

  const activeCount = goals.filter((g) => !g.completed).length;
  const completedCount = goals.filter((g) => g.completed).length;

  return (
    <div className="space-y-6">
      <GoalForm
        editingGoal={editingGoal}
        onSubmit={handleSubmit}
        onCancel={() => setEditingGoal(null)}
      />

      <div className="flex gap-2">
        {[
          { key: "all", label: `All (${goals.length})` },
          { key: "active", label: `Active (${activeCount})` },
          { key: "completed", label: `Completed (${completedCount})` },
        ].map(({ key, label }) => (
          <button
            key={key}
            onClick={() => setFilter(key)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
              filter === key
                ? "bg-green-600 text-white"
                : "bg-gray-100 text-gray-600 hover:bg-gray-200"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {filtered.length === 0 ? (
        <div className="text-center bg-white rounded-xl shadow p-10">
          <h2 className="text-xl font-semibold">No Goals Yet</h2>
          <p className="text-gray-500 mt-2">
            {filter === "completed"
              ? "You haven't completed any goals yet."
              : "Add your first savings goal to get started."}
          </p>
        </div>
      ) : (
        <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-3">
          {filtered.map((goal) => (
            <GoalCard
              key={goal.id}
              goal={goal}
              onEdit={setEditingGoal}
              onDelete={removeGoal}
              onComplete={completeGoal}
            />
          ))}
        </div>
      )}
    </div>
  );
}
