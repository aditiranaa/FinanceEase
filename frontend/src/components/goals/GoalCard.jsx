import { useEffect, useMemo, useRef, useState } from "react";
import {
  Calendar,
  MoreVertical,
  Pencil,
  Trash2,
  CheckCircle2,
} from "lucide-react";

import GoalProgress from "./GoalProgress";

const DAY = 1000 * 60 * 60 * 24;

const formatCurrency = (value) => {
  const amount = Number(value || 0);

  if (amount >= 10000000) return `₹${(amount / 10000000).toFixed(1)}Cr`;
  if (amount >= 100000) return `₹${(amount / 100000).toFixed(1)}L`;
  if (amount >= 1000) return `₹${(amount / 1000).toFixed(1)}K`;

  return `₹${amount.toLocaleString("en-IN")}`;
};

const getDaysLeft = (deadline) => {
  if (!deadline) return null;

  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const due = new Date(deadline);
  due.setHours(0, 0, 0, 0);

  return Math.ceil((due - today) / DAY);
};

export default function GoalCard({
  goal,
  onEdit,
  onDelete,
  onComplete,
}) {
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef(null);

  const saved = Number(goal.current_amount || 0);
  const target = Number(goal.target_amount || 0);

  const remaining = Math.max(target - saved, 0);

  const progress = target > 0 ? (saved / target) * 100 : 0;

  const days = getDaysLeft(goal.deadline);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (
        menuRef.current &&
        !menuRef.current.contains(event.target)
      ) {
        setMenuOpen(false);
      }
    };

    document.addEventListener(
      "mousedown",
      handleClickOutside
    );

    return () =>
      document.removeEventListener(
        "mousedown",
        handleClickOutside
      );
  }, []);

  const deadlineInfo = useMemo(() => {
    if (!goal.deadline) {
      return {
        text: "No deadline",
        className: "text-gray-400",
      };
    }

    if (days < 0) {
      return {
        text: `${Math.abs(days)} day${Math.abs(days) === 1 ? "" : "s"} overdue`,
        className: "font-semibold text-red-600",
      };
    }

    if (days === 0) {
      return {
        text: "Today",
        className: "font-semibold text-yellow-600",
      };
    }

    if (days <= 7) {
      return {
        text: `${days} day${days === 1 ? "" : "s"}`,
        className: "font-semibold text-yellow-600",
      };
    }

    return {
      text: `${days} day${days === 1 ? "" : "s"}`,
      className: "text-gray-500",
    };
  }, [goal.deadline, days]);

  return (
    <div
      className="
        bg-white
        dark:bg-gray-900
        rounded-2xl
        border
        border-gray-200
        dark:border-gray-700
        shadow-sm
        hover:shadow-xl
        hover:-translate-y-1
        transition-all
        duration-300
      "
    >
      <div className="p-4">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <span
              className="
                inline-flex
                items-center
                rounded-full
                border
                border-blue-200
                bg-blue-50
                px-3
                py-1
                text-xs
                font-medium
                text-blue-700
              "
            >
              {goal.category}
            </span>

            <h2
              className="
                mt-3
                break-words
                text-lg
                font-bold
                leading-tight
                text-gray-900
                dark:text-white
              "
            >
              {goal.title}
            </h2>

            {goal.completed && (
              <span
                className="
                  mt-2
                  inline-flex
                  items-center
                  rounded-full
                  border
                  border-green-200
                  bg-green-50
                  px-3
                  py-1
                  text-xs
                  font-medium
                  text-green-700
                "
              >
                ✓ Completed
              </span>
            )}
          </div>

          <div
            ref={menuRef}
            className="relative shrink-0"
          >
            <button
              type="button"
              onClick={() => setMenuOpen((v) => !v)}
              className="
                rounded-lg
                p-2
                transition
                hover:bg-gray-100
                dark:hover:bg-gray-800
              "
            >
              <MoreVertical size={18} />
            </button>

            {menuOpen && (
              <div
                className="
                  absolute
                  right-0
                  mt-2
                  w-52
                  overflow-hidden
                  rounded-2xl
                  border
                  border-gray-200
                  dark:border-gray-700
                  bg-white
                  dark:bg-gray-900
                  shadow-2xl
                  z-50
                "
              >
                <button
                  type="button"
                  onClick={() => {
                    onEdit(goal);
                    setMenuOpen(false);
                  }}
                  className="
                    flex
                    w-full
                    items-center
                    gap-3
                    px-4
                    py-3
                    transition
                    hover:bg-gray-100
                    dark:hover:bg-gray-800
                  "
                >
                  <Pencil size={16} />
                  Edit
                </button>

                {!goal.completed && (
                  <button
                    type="button"
                    onClick={() => {
                      onComplete(goal.id);
                      setMenuOpen(false);
                    }}
                    className="
                      flex
                      w-full
                      items-center
                      gap-3
                      px-4
                      py-3
                      transition
                      hover:bg-gray-100
                      dark:hover:bg-gray-800
                    "
                  >
                    <CheckCircle2 size={16} />
                    Mark Complete
                  </button>
                )}

                <button
                  type="button"
                  onClick={() => {
                    onDelete(goal.id);
                    setMenuOpen(false);
                  }}
                  className="
                    flex
                    w-full
                    items-center
                    gap-3
                    px-4
                    py-3
                    text-red-600
                    transition
                    hover:bg-red-50
                    dark:hover:bg-red-950/30
                  "
                >
                  <Trash2 size={16} />
                  Delete
                </button>
              </div>
            )}
          </div>
        </div>

        <div className="my-5 flex justify-center">
          <GoalProgress
            current={saved}
            target={target}
            completed={goal.completed}
          />
        </div>

        <div className="mb-5">
          <div className="mb-2 flex items-center justify-between text-xs text-gray-500">
            <span>Progress</span>
            <span>{Math.min(progress, 100).toFixed(0)}%</span>
          </div>

          <div className="h-2 overflow-hidden rounded-full bg-gray-200 dark:bg-gray-700">
            <div
              className="h-full rounded-full bg-blue-600 transition-all"
              style={{
                width: `${Math.min(progress, 100)}%`,
              }}
            />
          </div>
        </div>

        <div className="grid grid-cols-3 gap-3">
          <div className="rounded-xl bg-gray-50 dark:bg-gray-800 p-3">
            <p className="text-[10px] uppercase tracking-wide text-gray-400">
              Saved
            </p>

            <p className="mt-1 text-xs font-bold text-green-600">
              {formatCurrency(saved)}
            </p>
          </div>

          <div className="rounded-xl bg-gray-50 dark:bg-gray-800 p-3">
            <p className="text-[10px] uppercase tracking-wide text-gray-400">
              Target
            </p>

            <p className="mt-1 text-xs font-bold text-gray-900 dark:text-white">
              {formatCurrency(target)}
            </p>
          </div>

          <div className="rounded-xl bg-gray-50 dark:bg-gray-800 p-3">
            <p className="text-[10px] uppercase tracking-wide text-gray-400">
              Left
            </p>

            <p className="mt-1 text-xs font-bold text-gray-900 dark:text-white">
              {formatCurrency(remaining)}
            </p>
          </div>
        </div>

        {goal.deadline ? (
          <div
            className="
              mt-5
              flex
              items-center
              justify-between
              border-t
              border-gray-200
              dark:border-gray-700
              pt-4
              text-xs
            "
          >
            <div className="flex items-center gap-2 text-gray-500">
              <Calendar size={15} />
              {new Date(goal.deadline).toLocaleDateString("en-IN")}
            </div>

            <span className={deadlineInfo.className}>
              {deadlineInfo.text}
            </span>
          </div>
        ) : (
          <div
            className="
              mt-5
              border-t
              border-gray-200
              dark:border-gray-700
              pt-4
              text-xs
              text-gray-400
            "
          >
            No deadline
          </div>
        )}
      </div>
    </div>
  );
}