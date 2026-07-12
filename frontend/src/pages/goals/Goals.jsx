import { useState } from "react";

import AppLayout from "../../components/layout/AppLayout";

import useGoals from "../../hooks/useGoals";

import GoalHeader from "../../components/goals/GoalHeader";
import GoalOverview from "../../components/goals/GoalOverview";
import GoalAlerts from "../../components/goals/GoalAlerts";
import GoalToolbar from "../../components/goals/GoalToolbar";
import GoalGrid from "../../components/goals/GoalGrid";
import GoalModal from "../../components/goals/GoalModal";
import GoalSkeleton from "../../components/goals/GoalSkeleton";
import Navbar from "../../components/layout/Navbar";

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

  const [showModal, setShowModal] = useState(false);
  const [editingGoal, setEditingGoal] = useState(null);

  const openCreate = () => {
    setEditingGoal(null);
    setShowModal(true);
  };

  const openEdit = (goal) => {
    setEditingGoal(goal);
    setShowModal(true);
  };

  const handleSubmit = async (goalData) => {
    if (editingGoal) {
      await editGoal(editingGoal.id, goalData);
    } else {
      await addGoal(goalData);
    }

    setEditingGoal(null);
    setShowModal(false);
  };

  let filteredGoals = [...goals];

  // Search
  filteredGoals = filteredGoals.filter((goal) =>
    (goal.title || "")
      .toLowerCase()
      .includes(search.toLowerCase())
  );

  // Category
  if (category !== "all") {
    filteredGoals = filteredGoals.filter(
      (goal) => goal.category === category
    );
  }

  // Status
  if (status === "active") {
    filteredGoals = filteredGoals.filter(
      (goal) => !goal.completed
    );
  }

  if (status === "completed") {
    filteredGoals = filteredGoals.filter(
      (goal) => goal.completed
    );
  }

  // Sorting
  filteredGoals.sort((a, b) => {
    switch (sort) {
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

      default:
        return (
          new Date(a.deadline || 0) -
          new Date(b.deadline || 0)
        );
    }
  });

  return (
  <AppLayout>

    <div className="space-y-6">

      <GoalHeader onAdd={openCreate} />

      {loading && (
        <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <GoalSkeleton key={i} />
          ))}
        </div>
      )}

      {!loading && error && (
        <div className="text-center py-12 text-red-600">
          {error}
        </div>
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
          />

          <GoalGrid
            goals={filteredGoals}
            onEdit={openEdit}
            onDelete={removeGoal}
            onComplete={completeGoal}
          />
        </>
      )}

      <GoalModal
        open={showModal}
        editingGoal={editingGoal}
        onClose={() => {
          setShowModal(false);
          setEditingGoal(null);
        }}
        onSubmit={handleSubmit}
      />

    </div>

  </AppLayout>
);
}