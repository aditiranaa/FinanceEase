import { useState, useRef, useEffect } from "react";

import GoalProgress from "./GoalProgress";
import {
  Calendar,
  IndianRupee,
  MoreVertical,
  Pencil,
  Trash2,
  CheckCircle2,
} from "lucide-react";

const formatCurrency = (value) =>
  Number(value || 0).toLocaleString("en-IN", {
    style: "currency",
    currency: "INR",
    maximumFractionDigits: 0,
  });

const daysLeft = (deadline) => {
  if (!deadline) return null;

  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const due = new Date(deadline);
  due.setHours(0, 0, 0, 0);

  return Math.ceil(
    (due - today) /
      (1000 * 60 * 60 * 24)
  );
};

export default function GoalCard({
  goal,
  onEdit,
  onDelete,
  onComplete,
}) {
  const saved = Number(goal.current_amount);

  const target = Number(goal.target_amount);

  const remaining = Math.max(
    target - saved,
    0
  );

  const days = daysLeft(goal.deadline);

  const [menuOpen, setMenuOpen] = useState(false);

const menuRef = useRef(null);

useEffect(() => {
  const handleClick = (event) => {
    if (
      menuRef.current &&
      !menuRef.current.contains(event.target)
    ) {
      setMenuOpen(false);
    }
  };

  document.addEventListener(
    "mousedown",
    handleClick
  );

  return () =>
    document.removeEventListener(
      "mousedown",
      handleClick
    );
}, []);

  return (
    <div className="
            bg-white
            rounded-2xl
            border
            border-gray-200
            shadow-sm
            hover:shadow-xl
            hover:-translate-y-1
            transition-all
            duration-300
            ">

      <div className="p-6">

        {/* Header */}

        <div className="flex justify-between items-start">

          <div>

            <span className="bg-blue-100 text-blue-700 text-xs px-3 py-1 rounded-full">
              {goal.category}
            </span>

            <h2 className="mt-3 text-xl font-bold">
              {goal.title}
            </h2>

            {goal.completed && (
              <span className="inline-block mt-2 px-3 py-1 rounded-full bg-green-100 text-green-700 text-xs font-medium">
                Completed
              </span>
            )}

          </div>

          <div
  className="relative"
  ref={menuRef}
>

  <button
    onClick={() =>
      setMenuOpen(!menuOpen)
    }
    className="p-2 rounded-lg hover:bg-gray-100"
  >
    <MoreVertical size={18} />
  </button>

  {menuOpen && (

    <div className="absolute right-0 mt-2 w-48 bg-white rounded-xl shadow-xl border z-50">

      <button
        onClick={() => {
          onEdit(goal);
          setMenuOpen(false);
        }}
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-gray-100"
      >
        <Pencil size={16} />

        Edit
      </button>

      {!goal.completed && (
        <button
          onClick={() => {
            onComplete(goal.id);
            setMenuOpen(false);
          }}
          className="w-full flex items-center gap-3 px-4 py-3 hover:bg-gray-100"
        >
          <CheckCircle2 size={16} />

          Mark Complete
        </button>
      )}

      <button
        onClick={() => {
          onDelete(goal.id);
          setMenuOpen(false);
        }}
        className="w-full flex items-center gap-3 px-4 py-3 text-red-600 hover:bg-red-50"
      >
        <Trash2 size={16} />

        Delete
      </button>

    </div>

  )}

</div>

        </div>

        {/* Progress */}

        <div className="flex justify-center mt-8 mb-8">

          <GoalProgress
            current={saved}
            target={target}
            completed={goal.completed}
          />

        </div>

        {/* Stats */}

          <div className="grid grid-cols-3 gap-4 text-center border-t border-gray-100 pt-6">
          <div>

              <p className="text-xs text-gray-400">
                Saved
              </p>

              <p className="font-bold text-green-600">
                {formatCurrency(saved)}
              </p>

            </div>

            <div>

              <p className="text-xs text-gray-400">
                Target
              </p>

              <p className="font-bold">
                {formatCurrency(target)}
              </p>

            </div>

            <div>

              <p className="text-xs text-gray-400">
                Left
              </p>

              <p className="font-bold">
                {formatCurrency(remaining)}
              </p>

          </div>

        </div>

        {/* Footer */}

        {goal.deadline && (

          <div className="mt-6 flex justify-between text-sm">

            <div className="flex items-center gap-2 text-gray-500">

              <Calendar size={15} />

              {new Date(
                goal.deadline
              ).toLocaleDateString("en-IN")}

            </div>

            <span
              className={
              days < 0
                ? "text-red-600 font-semibold"
                : days <= 7
                ? "text-yellow-600 font-semibold"
                : "text-gray-500"
            }
            >
              {days < 0
              ? `${Math.abs(days)} days overdue`
              : days === 0
              ? "Due today"
              : `${days} days left`}
            </span>

          </div>

        )}

      </div>

    </div>
  );
}