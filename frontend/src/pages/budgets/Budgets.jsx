import useBudgets from "../../hooks/useBudgets";

import BudgetOverview from "../../components/budgets/BudgetOverview";
import BudgetAlerts from "../../components/budgets/BudgetAlerts";
import BudgetManager from "./BudgetManager";

export default function Budgets() {
  const {
    budgets,
    loading,
    error,
    addBudget,
    editBudget,
    removeBudget,
  } = useBudgets();

  if (loading) {
    return (
      <div className="flex justify-center items-center h-60">
        <p className="text-lg">Loading budgets...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-center text-red-600 py-10">
        {error}
      </div>
    );
  }

  return (
    <div className="space-y-8">

      <div>
        <h1 className="text-3xl font-bold">
          Budget Management
        </h1>

        <p className="text-gray-500">
          Manage and track your monthly budgets.
        </p>
      </div>

      <BudgetOverview budgets={budgets} />

      <BudgetAlerts budgets={budgets} />

      <BudgetManager
        budgets={budgets}
        addBudget={addBudget}
        editBudget={editBudget}
        removeBudget={removeBudget}
      />

    </div>
  );
}