import { useState } from "react";

import BudgetCard from "../../components/budgets/BudgetCard";
import BudgetForm from "../../components/budgets/BudgetForm";

export default function BudgetManager({
  budgets,
  addBudget,
  editBudget,
  removeBudget,
}) {
  const [editingBudget, setEditingBudget] = useState(null);

  const handleSubmit = async (budget) => {
    if (editingBudget) {
      await editBudget(editingBudget.id, budget);
      setEditingBudget(null);
    } else {
      await addBudget(budget);
    }
  };

  return (
    <div className="space-y-8">
      <BudgetForm
        editingBudget={editingBudget}
        onSubmit={handleSubmit}
        onCancel={() => setEditingBudget(null)}
      />

      {budgets.length === 0 ? (
        <div className="rounded-2xl border border-gray-200 bg-white py-16 text-center shadow-sm">
          <h2 className="text-2xl font-bold text-gray-900">
            No Budgets Yet
          </h2>

          <p className="mt-3 text-gray-500">
            Add your first monthly budget.
          </p>
        </div>
      ) : (
        <div className="space-y-5">
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