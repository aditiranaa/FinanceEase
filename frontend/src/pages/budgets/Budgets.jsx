import { useState } from "react";
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

  const [showCreateForm, setShowCreateForm] = useState(false);

  return (
    <div className="mx-auto w-full max-w-7xl px-8 py-8">
      <div className="mb-10 flex flex-col gap-6 md:flex-row md:items-start md:justify-between">
        <div>
          <h1 className="text-5xl font-extrabold tracking-tight text-gray-900">
            Budgets
          </h1>

          <p className="mt-3 text-lg text-gray-500">
            Track your spending and stay on top of your goals.
          </p>
        </div>

        <button
          type="button"
          onClick={() => setShowCreateForm((prev) => !prev)}
          className="flex h-14 items-center gap-3 rounded-xl bg-emerald-600 px-7 text-lg font-semibold text-white shadow-sm transition hover:bg-emerald-700"
        >
          <span className="text-3xl leading-none">+</span>
          <span>
            {showCreateForm ? "Close" : "Create Budget"}
          </span>
        </button>
      </div>

      {loading && (
        <div className="rounded-2xl border border-gray-200 bg-white py-12 text-center text-gray-500 shadow-sm">
          Loading budgets...
        </div>
      )}

      {error && (
        <div className="rounded-2xl border border-red-200 bg-red-50 py-12 text-center text-red-600 shadow-sm">
          Failed to load budgets. Please try again.
        </div>
      )}

      {!loading && !error && (
        <div className="space-y-8">
          <BudgetOverview budgets={budgets} />

          <BudgetAlerts budgets={budgets} />

          <BudgetManager
            budgets={budgets}
            addBudget={addBudget}
            editBudget={editBudget}
            removeBudget={removeBudget}
            showCreateForm={showCreateForm}
            setShowCreateForm={setShowCreateForm}
          />
        </div>
      )}
    </div>
  );
}