import {
  AlertTriangle,
  Clock3,
  Trophy,
} from "lucide-react";

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

export default function GoalAlerts({
  goals,
}) {
  const overdue = goals.filter((goal) => {
    const days = daysLeft(goal.deadline);

    return (
      !goal.completed &&
      days !== null &&
      days < 0
    );
  });

  const upcoming = goals.filter((goal) => {
    const days = daysLeft(goal.deadline);

    return (
      !goal.completed &&
      days !== null &&
      days >= 0 &&
      days <= 7
    );
  });

  const completed = goals.filter(
    (goal) => goal.completed
  );

  if (
    overdue.length === 0 &&
    upcoming.length === 0 &&
    completed.length === 0
  ) {
    return null;
  }

  return (
    <div className="grid gap-4 lg:grid-cols-3">

      {overdue.length > 0 && (
        <div className="rounded-2xl border border-red-200 bg-red-50 p-5">

          <AlertTriangle
            className="text-red-600"
            size={28}
          />

          <h3 className="mt-3 font-bold text-red-700">
            Overdue Goals
          </h3>

          <p className="mt-2 text-red-600 text-sm">
            {overdue.length} goal(s) have crossed their deadline.
          </p>

        </div>
      )}

      {upcoming.length > 0 && (
        <div className="rounded-2xl border border-yellow-200 bg-yellow-50 p-5">

          <Clock3
            className="text-yellow-600"
            size={28}
          />

          <h3 className="mt-3 font-bold text-yellow-700">
            Upcoming Deadlines
          </h3>

          <p className="mt-2 text-yellow-700 text-sm">
            {upcoming.length} goal(s) are due within a week.
          </p>

        </div>
      )}

      {completed.length > 0 && (
        <div className="rounded-2xl border border-green-200 bg-green-50 p-5">

          <Trophy
            className="text-green-600"
            size={28}
          />

          <h3 className="mt-3 font-bold text-green-700">
            Completed Goals
          </h3>

          <p className="mt-2 text-green-700 text-sm">
            Great job! You've completed {completed.length} goal(s).
          </p>

        </div>
      )}

    </div>
  );
}