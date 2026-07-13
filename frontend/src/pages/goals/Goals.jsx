import { useMemo, useState } from "react";

import AppLayout from "../../components/layout/AppLayout";

import useGoals from "../../hooks/useGoals";

import GoalOverview from "../../components/goals/GoalOverview";
import GoalAlerts from "../../components/goals/GoalAlerts";
import GoalToolbar from "../../components/goals/GoalToolbar";
import GoalGrid from "../../components/goals/GoalGrid";
import GoalModal from "../../components/goals/GoalModal";

import GoalForm from "../../components/goals/GoalForm";
export default function Goals() {
  const {
    goals,
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

  const filteredGoals = useMemo(() => {
    let data = [...goals];

    data = data.filter((goal) =>
      (goal.title || "")
        .toLowerCase()
        .includes(search.toLowerCase())
    );

    if (category !== "all") {
      data = data.filter(
        (goal) => goal.category === category
      );
    }

    if (status === "active") {
      data = data.filter((goal) => !goal.completed);
    }

    if (status === "completed") {
      data = data.filter((goal) => goal.completed);
    }

    data.sort((a, b) => {
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
            Number(a.current_amount) /
            Number(a.target_amount || 1);

          const progressB =
            Number(b.current_amount) /
            Number(b.target_amount || 1);

          return progressB - progressA;
        }

        case "deadline":
        default:
          return (
            new Date(a.deadline || 0) -
            new Date(b.deadline || 0)
          );
      }
    });

    return data;
  }, [goals, search, category, status, sort]);

  return (
    <AppLayout>
      <div className="space-y-4">
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
          onAdd={openCreate}
        />

        <GoalGrid
          goals={filteredGoals}
          onEdit={openEdit}
          onDelete={removeGoal}
          onComplete={completeGoal}
        />
      </div>

      <GoalModal
  open={showModal}
  editingGoal={editingGoal}
  onClose={() => {
    setShowModal(false);
    setEditingGoal(null);
  }}
>
  <GoalForm
    editingGoal={editingGoal}
    onSubmit={handleSubmit}
    onCancel={() => {
      setShowModal(false);
      setEditingGoal(null);
    }}
  />
</GoalModal>
    </AppLayout>
  );
}