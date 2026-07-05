import { Link } from "react-router-dom";

import useGoals from "../../hooks/useGoals";
import GoalProgress from "../goals/GoalProgress";

const SavingsGoals = () => {
  const { goals, loading, addGoal } = useGoals();

  const activeGoals = goals.filter((g) => !g.completed).slice(0, 3);

  const handleQuickAdd = async (e) => {
    e.preventDefault();
    const form = e.target;
    const title = form.title.value.trim();
    const target_amount = form.target_amount.value;
    const current_amount = form.current_amount.value || "0";

    if (!title || !target_amount) return;

    await addGoal({ title, target_amount, current_amount, category: "General" });
    form.reset();
  };

  return (
    <div className="bg-white p-6 rounded-2xl shadow-sm mt-8">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold">Savings Goals</h2>
        <Link
          to="/goals"
          className="text-sm text-green-600 hover:text-green-700 font-medium"
        >
          View all →
        </Link>
      </div>

      <form onSubmit={handleQuickAdd} className="space-y-4">
        <input
          type="text"
          name="title"
          placeholder="Goal Name"
          className="w-full border p-3 rounded-lg"
          required
        />

        <div className="grid grid-cols-2 gap-3">
          <input
            type="number"
            name="target_amount"
            placeholder="Target Amount"
            className="w-full border p-3 rounded-lg"
            required
            min="0"
          />

          <input
            type="number"
            name="current_amount"
            placeholder="Current Amount"
            className="w-full border p-3 rounded-lg"
            min="0"
          />
        </div>

        <button
          type="submit"
          className="bg-green-500 text-white px-5 py-3 rounded-lg hover:bg-green-600"
        >
          Add Goal
        </button>
      </form>

      <div className="mt-6 space-y-4">
        {loading ? (
          <p className="text-gray-400">Loading...</p>
        ) : activeGoals.length === 0 ? (
          <p className="text-gray-400">No active goals yet</p>
        ) : (
          activeGoals.map((goal) => {
            const current = Number(goal.current_amount);
            const target = Number(goal.target_amount);
            const percentage =
              target > 0
                ? Math.min((current / target) * 100, 100)
                : 0;

            return (
              <div key={goal.id} className="bg-gray-50 p-4 rounded-xl">
                <h3 className="font-semibold text-gray-800">{goal.title}</h3>

                <p className="text-gray-500 mt-1">
                  ₹{current.toLocaleString("en-IN")}
                  {" / "}
                  ₹{target.toLocaleString("en-IN")}
                </p>

                <div className="mt-3">
                  <GoalProgress current={current} target={target} />
                </div>

                <p className="text-sm text-gray-500 mt-2">
                  {percentage.toFixed(0)}% Complete
                </p>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};

export default SavingsGoals;
