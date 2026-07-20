import { Link } from "react-router-dom";
import {
  Target,
  Plus,
  ArrowRight,
  RefreshCw,
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

  const totalSaved = activeGoals.reduce(
    (sum, goal) => sum + Number(goal.current_amount || 0),
    0
  );

  const handleQuickAdd = async (e) => {
    e.preventDefault();

    const form = e.target;

    const title = form.title.value.trim();
    const target_amount = form.target_amount.value;
    const current_amount =
      form.current_amount.value || "0";

    if (!title || !target_amount) return;

    await addGoal({
      title,
      target_amount,
      current_amount,
      category: "General",
    });

    form.reset();
  };

  const inputClass =
    "h-12 w-full rounded-2xl border border-slate-200 bg-white px-4 text-sm text-slate-800 outline-none transition-all placeholder:text-slate-400 focus:border-blue-500 focus:ring-4 focus:ring-blue-500/10";

  return (
    <section className="rounded-[32px] border border-slate-200/70 bg-white p-8 shadow-sm">

      {/* Header */}

      <div className="mb-10 flex items-start justify-between">

        <div className="flex items-center gap-5">

          <div className="flex h-16 w-16 items-center justify-center rounded-3xl bg-gradient-to-br from-emerald-500 to-teal-500 shadow-lg shadow-emerald-500/20">

            <Target
              size={30}
              className="text-white"
            />

          </div>

          <div>

            <span className="inline-flex rounded-full bg-emerald-50 px-3 py-1 text-xs font-semibold text-emerald-700">
              {activeGoals.length} Active Goals
            </span>

            <h2 className="mt-3 text-3xl font-bold tracking-tight text-slate-900">
              Savings Goals
            </h2>

            <p className="mt-1 text-slate-500">
              Build wealth one milestone at a time.
            </p>

          </div>

        </div>

        <Link
          to="/goals"
          className="flex items-center gap-2 rounded-2xl border border-slate-200 bg-white px-5 py-3 text-sm font-semibold text-slate-700 transition-all hover:border-blue-200 hover:bg-blue-50"
        >
          View All
          <ArrowRight size={17} />
        </Link>

      </div>

      {/* Summary */}

      <div className="mb-8 grid gap-4 md:grid-cols-2">

        <div className="rounded-3xl bg-gradient-to-r from-blue-600 to-indigo-600 p-6 text-white">

          <p className="text-sm text-blue-100">
            Total Saved
          </p>

          <h3 className="mt-2 text-4xl font-bold tracking-tight">
            ₹{totalSaved.toLocaleString("en-IN")}
          </h3>

          <p className="mt-2 text-sm text-blue-100">
            Across {activeGoals.length} active goals
          </p>

        </div>

        <div className="rounded-3xl border border-slate-200 bg-slate-50 p-6">

          <h3 className="text-lg font-bold text-slate-900">
            Quick Add Goal
          </h3>

          <p className="mt-1 text-sm text-slate-500">
            Create a new savings target in seconds.
          </p>

        </div>

      </div>

      {/* Quick Add */}

      <form
        onSubmit={handleQuickAdd}
        className="rounded-3xl border border-slate-200 bg-slate-50 p-6"
      >

        <div className="grid gap-4">

          <input
            type="text"
            name="title"
            placeholder="Goal name"
            required
            className={inputClass}
          />

          <div className="grid gap-4 md:grid-cols-2">

            <input
              type="number"
              name="target_amount"
              placeholder="Target amount"
              required
              min="0"
              className={inputClass}
            />

            <input
              type="number"
              name="current_amount"
              placeholder="Current saved"
              min="0"
              className={inputClass}
            />

          </div>

          <button
            type="submit"
            className="flex h-12 items-center justify-center gap-2 rounded-2xl bg-gradient-to-r from-emerald-500 to-teal-500 font-semibold text-white shadow-lg shadow-emerald-500/20 transition-all hover:-translate-y-0.5 hover:shadow-xl hover:shadow-emerald-500/30"
          >
            <Plus size={18} />
            Add Goal
          </button>

        </div>

      </form>

      {/* Goals */}

      <div className="mt-10 space-y-5">

                {loading ? (
          <div className="rounded-3xl border border-slate-200 bg-slate-50 py-16 text-center">
            <RefreshCw
              size={30}
              className="mx-auto animate-spin text-blue-600"
            />

            <p className="mt-4 text-sm font-medium text-slate-500">
              Loading your savings goals...
            </p>
          </div>
        ) : activeGoals.length === 0 ? (
          <div className="rounded-3xl border border-dashed border-slate-200 bg-slate-50 py-16 text-center">
            <div className="mx-auto flex h-20 w-20 items-center justify-center rounded-3xl bg-white shadow-sm">
              <Target
                size={34}
                className="text-slate-300"
              />
            </div>

            <h3 className="mt-6 text-2xl font-bold text-slate-900">
              No savings goals yet
            </h3>

            <p className="mx-auto mt-2 max-w-sm text-sm text-slate-500">
              Create your first goal and start building toward your next
              financial milestone.
            </p>
          </div>
        ) : (
          activeGoals.map((goal) => {
            const current = Number(
              goal.current_amount || 0
            );

            const target = Number(
              goal.target_amount || 0
            );

            const percentage =
              target > 0
                ? Math.min(
                    (current / target) * 100,
                    100
                  )
                : 0;

            const remaining = Math.max(
              target - current,
              0
            );

            return (
              <div
                key={goal.id}
                className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm transition-all duration-300 hover:-translate-y-1 hover:shadow-xl"
              >
                <div className="flex items-start justify-between">

                  <div>

                    <div className="inline-flex rounded-full bg-blue-50 px-3 py-1 text-xs font-semibold text-blue-700">
                      {goal.category || "General"}
                    </div>

                    <h3 className="mt-3 text-xl font-bold text-slate-900">
                      {goal.title}
                    </h3>

                    <p className="mt-1 text-sm text-slate-500">
                      ₹{current.toLocaleString("en-IN")} of ₹
                      {target.toLocaleString("en-IN")}
                    </p>

                  </div>

                  <div className="rounded-2xl bg-emerald-50 px-4 py-2 text-right">
                    <p className="text-2xl font-bold text-emerald-700">
                      {percentage.toFixed(0)}%
                    </p>

                    <p className="text-xs text-emerald-600">
                      Complete
                    </p>
                  </div>

                </div>

                <div className="mt-6">
                  <GoalProgress
                    current={current}
                    target={target}
                  />
                </div>

                <div className="mt-5 flex items-center justify-between border-t border-slate-100 pt-5">

                  <div>
                    <p className="text-xs uppercase tracking-wide text-slate-400">
                      Remaining
                    </p>

                    <p className="mt-1 text-lg font-bold text-slate-900">
                      ₹{remaining.toLocaleString("en-IN")}
                    </p>
                  </div>

                  <div className="text-right">
                    <p className="text-xs uppercase tracking-wide text-slate-400">
                      Target
                    </p>

                    <p className="mt-1 text-lg font-bold text-slate-900">
                      ₹{target.toLocaleString("en-IN")}
                    </p>
                  </div>

                </div>
              </div>
            );
          })
        )}
      </div>

    </section>
  );
}