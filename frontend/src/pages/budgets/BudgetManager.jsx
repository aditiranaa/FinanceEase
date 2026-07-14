import { useState } from "react";

import BudgetCard from "../../components/budgets/BudgetCard";
import BudgetForm from "../../components/budgets/BudgetForm";

export default function BudgetManager({
  budgets,
  addBudget,
  editBudget,
  removeBudget,
}) {
  const [editingBudget, setEditingBudget] =
    useState(null);

  const handleSubmit = async (budget) => {
    if (editingBudget) {
      await editBudget(editingBudget.id, budget);
      setEditingBudget(null);
    } else {
      await addBudget(budget);
    }
  };

  return (
    <div className="space-y-4">

      <BudgetForm
        editingBudget={editingBudget}
        onSubmit={handleSubmit}
        onCancel={() => setEditingBudget(null)}
      />

      {budgets.length === 0 ? (
        <div className="text-center bg-white rounded-xl shadow p-10">
          <h2 className="text-lg font-semibold">
            No Budgets Yet
          </h2>

          <p className="text-gray-500 mt-2">
            Add your first monthly budget.
          </p>
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">

          {budgets.map((budget) => (
            <BudgetCard
              key={budget.id}
              budget={budget}
              onEdit={setEditingBudget}
              onDelete={removeBudget}
            />
          ))}

        </div>
      )}

    </div>
  );
}