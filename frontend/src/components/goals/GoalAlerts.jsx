import {
  AlertTriangle,
  Clock3,
  CheckCircle2,
} from "lucide-react";

const daysUntil = (deadline) => {
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
  goals = [],
}) {
  const alerts = [];

  goals.forEach((goal) => {
    if (goal.completed) {
      alerts.push({
        id: `${goal.id}-completed`,
        type: "success",
        icon: CheckCircle2,
        message: `"${goal.title}" completed successfully.`,
      });

      return;
    }

    const days = daysUntil(goal.deadline);

    if (
      days !== null &&
      days >= 0 &&
      days <= 7
    ) {
      alerts.push({
        id: `${goal.id}-deadline`,
        type: "warning",
        icon: Clock3,
        message: `"${goal.title}" is due in ${days} day${
          days !== 1 ? "s" : ""
        }.`,
      });
    }

    const progress =
      Number(goal.target_amount) === 0
        ? 0
        : (Number(goal.current_amount) /
            Number(goal.target_amount)) *
          100;

    if (
      progress >= 80 &&
      progress < 100
    ) {
      alerts.push({
        id: `${goal.id}-progress`,
        type: "info",
        icon: AlertTriangle,
        message: `"${goal.title}" is ${Math.round(
          progress
        )}% complete.`,
      });
    }
  });

  if (!alerts.length) return null;

  const colors = {
    success:
      "bg-green-50 border-green-200 text-green-700",
    warning:
      "bg-yellow-50 border-yellow-200 text-yellow-700",
    info:
      "bg-blue-50 border-blue-200 text-blue-700",
  };

  return (
    <div className="space-y-3">

      {alerts.slice(0, 3).map((alert) => {
        const Icon = alert.icon;

        return (
          <div
            key={alert.id}
            className={`flex items-center gap-3 rounded-xl border px-5 py-4 ${colors[alert.type]}`}
          >
            <Icon size={20} />

            <p className="font-medium">
              {alert.message}
            </p>
          </div>
        );
      })}

    </div>
  );
}