import { useState } from "react";

import GoalGrid from "../../components/goals/GoalGrid";
import GoalFormCollapse from "../../components/goals/GoalFormCollapse";

import DeleteGoalModal from "../../components/goals/DeleteGoalModal";

export default function GoalManager({
  goals,
  addGoal,
  editGoal,
  removeGoal,
  completeGoal,
  showForm,
  setShowForm,
  search,
  category,
  status,
  sort,
}) {
  const [editingGoal, setEditingGoal] = useState(null);
  const [deleteGoal, setDeleteGoal] =
  useState(null);

  const handleSubmit = async (goal) => {
    if (editingGoal) {
      await editGoal(editingGoal.id, goal);
      setEditingGoal(null);
    } else {
      await addGoal(goal);
    }

    setShowForm(false);
  };

  let filtered = [...goals];

  // Search
  filtered = filtered.filter((goal) =>
  (goal.title ?? "")
    .toLowerCase()
    .includes((search ?? "").toLowerCase())
);

  // Category
  if ((category ?? "all") !== "all") { 
    filtered = filtered.filter(
      (goal) => goal.category === category
    );
  }

  // Status
  if ((status ?? "all") === "active") {
    filtered = filtered.filter(
      (goal) => !goal.completed
    );
  }

  if ((status ?? "all") === "completed") {
    filtered = filtered.filter(
      (goal) => goal.completed
    );
  }

  // Sorting
  filtered.sort((a, b) => {
    switch (sort) {
      case "progress": {
        const progressA =
          Number(a.target_amount) === 0
            ? 0
            : Number(a.current_amount) /
              Number(a.target_amount);

        const progressB =
          Number(b.target_amount) === 0
            ? 0
            : Number(b.current_amount) /
              Number(b.target_amount);

        return progressB - progressA;
      }

      case "saved":
        return (
          Number(b.current_amount) -
          Number(a.current_amount)
        );

      case "target":
        return (
          Number(b.target_amount) -
          Number(a.target_amount)
        );

      default:
        return (
          new Date(a.deadline || 0) -
          new Date(b.deadline || 0)
        );
    }
  });

  return (
    <div className="space-y-8">

      {filtered.length === 0 ? (
        <div className="bg-white rounded-2xl shadow-sm p-12 text-center">
            <div className="text-6xl">
          🎯
        </div>

          <h2 className="mt-6 text-2xl font-bold">
            {goals.length === 0
              ? "Start Saving Today"
              : "No Matching Goals"}
          </h2>

          <p className="mt-3 text-gray-500">
            {goals.length === 0
              ? "Create your first savings goal and start tracking your progress."
              : "Try adjusting your search or filters."}
          </p>

          {goals.length === 0 && (
            <button
              onClick={() => setShowForm(true)}
              className="mt-6 px-6 py-3 rounded-xl bg-blue-600 text-white hover:bg-blue-700 transition"
            >
              Create Goal
            </button>
          )}

        </div>
      ) : (
        <GoalGrid
  goals={filtered}
  onEdit={(goal) => {
    setEditingGoal(goal);
    setShowForm(true);
  }}
  onDelete={(id) => {
    const goal = goals.find(
      (g) => g.id === id
    );

    setDeleteGoal(goal);
  }}
  onComplete={completeGoal}
/>
      )}

      <GoalFormCollapse
  show={showForm}
  editingGoal={editingGoal}
  onSubmit={handleSubmit}
  onCancel={() => {
    setEditingGoal(null);
    setShowForm(false);
  }}
/>

      <DeleteGoalModal
        open={!!deleteGoal}
        goal={deleteGoal}
        onClose={() => setDeleteGoal(null)}
        onConfirm={async () => {
          await removeGoal(deleteGoal.id);
          setDeleteGoal(null);
        }}
      />

    </div>
  );
}