import GoalProgress from "./GoalProgress";
import {
  Pencil,
  Trash2,
  IndianRupee,
  Calendar,
  CheckCircle2,
} from "lucide-react";

const formatCurrency = (amount) =>
  Number(amount || 0).toLocaleString("en-IN", {
    style: "currency",
    currency: "INR",
  });

const formatDeadline = (deadline) => {
  if (!deadline) return null;
  const date = new Date(deadline);
  return date.toLocaleDateString("en-IN", {
    day: "numeric",
    month: "short",
    year: "numeric",
  });
};

const daysUntil = (deadline) => {
  if (!deadline) return null;
  const now = new Date();
  now.setHours(0, 0, 0, 0);
  const target = new Date(deadline);
  target.setHours(0, 0, 0, 0);
  return Math.ceil((target - now) / (1000 * 60 * 60 * 24));
};

export default function GoalCard({
  goal,
  onEdit,
  onDelete,
  onComplete,
}) {
  const target = Number(goal.target_amount);
  const current = Number(goal.current_amount);
  const remaining = target - current;
  const deadline = formatDeadline(goal.deadline);
  const days = daysUntil(goal.deadline);
  const isOverdue = days !== null && days < 0 && !goal.completed;

  return (
    <div
      className={`bg-white dark:bg-gray-900 rounded-xl shadow-md border p-6 transition hover:shadow-lg ${
        goal.completed
          ? "border-green-300 dark:border-green-700"
          : isOverdue
          ? "border-red-300 dark:border-red-700"
          : "border-gray-200 dark:border-gray-800"
      }`}
    >
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
              {goal.title}
            </h2>
            {goal.completed && (
              <span className="text-xs bg-green-100 text-green-700 px-2 py-0.5 rounded-full">
                Completed
              </span>
            )}
          </div>

          <p className="text-sm text-gray-500">{goal.category}</p>
        </div>

        <div className="flex gap-2">
          {!goal.completed && (
            <button
              onClick={() => onComplete(goal.id)}
              title="Mark complete"
              className="p-2 rounded-lg bg-green-100 hover:bg-green-200 text-green-600"
            >
              <CheckCircle2 size={18} />
            </button>
          )}

          <button
            onClick={() => onEdit(goal)}
            className="p-2 rounded-lg bg-blue-100 hover:bg-blue-200 text-blue-600"
          >
            <Pencil size={18} />
          </button>

          <button
            onClick={() => onDelete(goal.id)}
            className="p-2 rounded-lg bg-red-100 hover:bg-red-200 text-red-600"
          >
            <Trash2 size={18} />
          </button>
        </div>
      </div>

      <div className="mt-5">
        <GoalProgress
          current={current}
          target={target}
          completed={goal.completed}
        />
      </div>

      <div className="grid grid-cols-3 gap-4 mt-6">
        <div>
          <p className="text-xs text-gray-500">Saved</p>
          <div className="flex items-center gap-1 font-semibold text-green-600">
            <IndianRupee size={16} />
            {formatCurrency(current)}
          </div>
        </div>

        <div>
          <p className="text-xs text-gray-500">Target</p>
          <div className="flex items-center gap-1 font-semibold">
            <IndianRupee size={16} />
            {formatCurrency(target)}
          </div>
        </div>

        <div>
          <p className="text-xs text-gray-500">Remaining</p>
          <div
            className={`flex items-center gap-1 font-semibold ${
              remaining <= 0 ? "text-green-600" : "text-gray-700"
            }`}
          >
            <IndianRupee size={16} />
            {formatCurrency(Math.max(0, remaining))}
          </div>
        </div>
      </div>

      {deadline && (
        <div
          className={`mt-4 flex items-center gap-2 text-sm ${
            isOverdue
              ? "text-red-600"
              : days !== null && days <= 7
              ? "text-yellow-600"
              : "text-gray-500"
          }`}
        >
          <Calendar size={14} />
          {goal.completed ? (
            <span>Deadline: {deadline}</span>
          ) : isOverdue ? (
            <span>Overdue by {Math.abs(days)} days</span>
          ) : days === 0 ? (
            <span>Due today</span>
          ) : (
            <span>
              {deadline} ({days} days left)
            </span>
          )}
        </div>
      )}
    </div>
  );
}
