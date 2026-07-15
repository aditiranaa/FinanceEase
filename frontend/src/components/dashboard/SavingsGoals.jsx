import { Link } from "react-router-dom";
import {
  Target,
  Plus,
  ArrowRight,
} from "lucide-react";

import useGoals from "../../hooks/useGoals";
import GoalProgress from "../goals/GoalProgress";

export default function SavingsGoals() {
  const {
    goals,
    loading,
    addGoal,
  } = useGoals();

  const activeGoals = goals
    .filter((goal) => !goal.completed)
    .slice(0, 3);

  const handleQuickAdd = async (e) => {
    e.preventDefault();

    const form = e.target;

    const title =
      form.title.value.trim();

    const target_amount =
      form.target_amount.value;

    const current_amount =
      form.current_amount.value || "0";

    if (!title || !target_amount)
      return;

    await addGoal({
      title,
      target_amount,
      current_amount,
      category: "General",
    });

    form.reset();
  };

  const inputClass =
    "h-12 w-full rounded-xl border border-gray-200 bg-gray-50 px-4 outline-none transition focus:border-emerald-500 focus:bg-white focus:ring-4 focus:ring-emerald-100";

  return (
    <section className="rounded-3xl border border-gray-200 bg-white p-7 shadow-sm">
      <div className="mb-8 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-emerald-100">
            <Target
              className="text-emerald-600"
              size={28}
            />
          </div>

          <div>
            <h2 className="text-2xl font-bold text-gray-900">
              Savings Goals
            </h2>

            <p className="mt-1 text-sm text-gray-500">
              Track your financial milestones.
            </p>
          </div>
        </div>

        <Link
          to="/goals"
          className="flex items-center gap-2 rounded-xl bg-gray-100 px-4 py-2 text-sm font-semibold text-gray-700 transition hover:bg-gray-200"
        >
          View All
          <ArrowRight size={16} />
        </Link>
      </div>

      {/* Quick Add */}

      <form
        onSubmit={handleQuickAdd}
        className="space-y-4 rounded-2xl border border-gray-100 bg-gray-50 p-5"
      >
        <div className="grid gap-4">
          <input
            type="text"
            name="title"
            placeholder="Goal Name"
            className={inputClass}
            required
          />

          <div className="grid gap-4 md:grid-cols-2">
            <input
              type="number"
              name="target_amount"
              placeholder="Target Amount"
              min="0"
              required
              className={inputClass}
            />

            <input
              type="number"
              name="current_amount"
              placeholder="Current Saved"
              min="0"
              className={inputClass}
            />
          </div>

          <button
            type="submit"
            className="flex h-12 items-center justify-center gap-2 rounded-xl bg-emerald-600 font-semibold text-white transition hover:bg-emerald-700"
          >
            <Plus size={18} />
            Add Goal
          </button>
        </div>
      </form>

      {/* Goals */}

      <div className="mt-8 space-y-5">
        {loading ? (
          <div className="rounded-2xl border border-dashed border-gray-200 bg-gray-50 py-12 text-center text-gray-500">
            Loading goals...
          </div>
        ) : activeGoals.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-gray-200 bg-gray-50 py-12 text-center">
            <Target
              size={42}
              className="mx-auto mb-4 text-gray-300"
            />

            <h3 className="text-lg font-semibold text-gray-800">
              No Active Goals
            </h3>

            <p className="mt-2 text-sm text-gray-500">
              Create your first savings goal to start
              tracking your progress.
            </p>
          </div>
        ) : (
          activeGoals.map((goal) => {
            const current = Number(
              goal.current_amount
            );

            const target = Number(
              goal.target_amount
            );

            const percentage =
              target > 0
                ? Math.min(
                    (current / target) * 100,
                    100
                  )
                : 0;

            return (
              <div
                key={goal.id}
                className="rounded-2xl border border-gray-100 bg-gray-50 p-5 transition hover:border-emerald-200 hover:bg-white"
              >
                <div className="mb-4 flex items-start justify-between">
                  <div>
                    <h3 className="text-lg font-semibold text-gray-900">
                      {goal.title}
                    </h3>

                    <p className="mt-1 text-sm text-gray-500">
                      ₹
                      {current.toLocaleString(
                        "en-IN"
                      )}{" "}
                      of ₹
                      {target.toLocaleString(
                        "en-IN"
                      )}
                    </p>
                  </div>

                  <div className="rounded-full bg-emerald-100 px-3 py-1 text-sm font-semibold text-emerald-700">
                    {percentage.toFixed(0)}%
                  </div>
                </div>

                <GoalProgress
                  current={current}
                  target={target}
                />
              </div>
            );
          })
        )}
      </div>
    </section>
  );
}