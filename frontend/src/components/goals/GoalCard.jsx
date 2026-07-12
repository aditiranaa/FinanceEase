import { useState, useRef, useEffect } from "react";

import GoalProgress from "./GoalProgress";
import {
  Calendar,
  MoreVertical,
  Pencil,
  Trash2,
  CheckCircle2,
} from "lucide-react";

const formatCurrency = (value) => {
  const amount = Number(value || 0);

  if (amount >= 10000000)
    return `₹${(amount / 10000000).toFixed(1)}Cr`;

  if (amount >= 100000)
    return `₹${(amount / 100000).toFixed(1)}L`;

  if (amount >= 1000)
    return `₹${(amount / 1000).toFixed(1)}K`;

  return `₹${amount.toLocaleString("en-IN")}`;
};

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
              <span className="inline-flex items-center rounded-full bg-blue-50 text-blue-700 border border-blue-200 px-3 py-1 text-xs font-medium">
              {goal.category}
            </span>

            <h2 className="mt-3 text-2xl font-bold text-gray-900 break-words leading-tight">
              {goal.title}
            </h2>

            {goal.completed && (
              <span className="inline-block mt-2 px-3 py-1 rounded-full bg-green-50 border border-green-200 text-green-700 text-xs font-medium">
                ✓ Completed              
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
    className="p-2 rounded-lg transition hover:bg-gray-100"
  >
    <MoreVertical size={18} />
  </button>

  {menuOpen && (

    <div className="
          absolute
          right-0
          mt-2
          w-52
          rounded-2xl
          bg-white
          border
          border-gray-200
          shadow-2xl
          overflow-hidden
          z-50
          ">

      <button
        onClick={() => {
          onEdit(goal);
          setMenuOpen(false);
        }}
        className="w-full flex items-center gap-3 px-4 py-3 transition hover:bg-gray-100"
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
          className="w-full flex items-center gap-3 px-4 py-3 transition hover:bg-gray-100"
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

<div className="flex justify-center my-5">

  <GoalProgress
    current={saved}
    target={target}
    completed={goal.completed}
  />

</div>

{/* Stats */}

<div className="mt-4 grid grid-cols-3 gap-3">

  <div className="rounded-xl bg-gray-50 p-3">

    <p className="text-[10px] uppercase tracking-wide text-gray-400">
      Saved
    </p>

    <p className="mt-1 text-sm font-bold text-green-600">
      {formatCurrency(saved)}
    </p>

  </div>

  <div className="rounded-xl bg-gray-50 p-3">

    <p className="text-[10px] uppercase tracking-wide text-gray-400">
      Target
    </p>

    <p className="mt-1 text-sm font-bold text-gray-900">
      {formatCurrency(target)}
    </p>

  </div>

  <div className="rounded-xl bg-gray-50 p-3">

    <p className="text-[10px] uppercase tracking-wide text-gray-400">
      Left
    </p>

    <p className="mt-1 text-sm font-bold text-gray-900">
      {formatCurrency(remaining)}
    </p>

  </div>

</div>
{goal.deadline ? (

<div className="mt-5 flex items-center justify-between border-t pt-4 text-sm">

  <div className="flex items-center gap-2 text-gray-500">

    <Calendar size={15} />

    {new Date(goal.deadline).toLocaleDateString("en-IN")}

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
      ? `${Math.abs(days)} overdue`
      : days === 0
      ? "Today"
      : `${days} days`}
  </span>

</div>

) : (

<div className="mt-5 border-t pt-4 text-sm text-gray-400">
  No deadline
</div>

)}

      </div>

    </div>
  );
}