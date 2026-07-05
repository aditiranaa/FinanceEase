import { AlertTriangle, CheckCircle, Clock } from "lucide-react";

const daysUntil = (deadline) => {
  if (!deadline) return null;
  const now = new Date();
  now.setHours(0, 0, 0, 0);
  const target = new Date(deadline);
  target.setHours(0, 0, 0, 0);
  return Math.ceil((target - now) / (1000 * 60 * 60 * 24));
};

export default function GoalAlerts({ goals = [] }) {
  const active = goals.filter((g) => !g.completed);

  const overdue = active.filter((g) => {
    const days = daysUntil(g.deadline);
    return days !== null && days < 0;
  });

  const dueSoon = active.filter((g) => {
    const days = daysUntil(g.deadline);
    return days !== null && days >= 0 && days <= 7;
  });

  const nearComplete = active.filter((g) => {
    const target = Number(g.target_amount);
    const current = Number(g.current_amount);
    if (target === 0) return false;
    const pct = (current / target) * 100;
    return pct >= 80 && pct < 100;
  });

  const alerts = [
    ...overdue.map((g) => ({
      goal: g,
      type: "overdue",
      message: `"${g.title}" is overdue`,
    })),
    ...dueSoon.map((g) => {
      const days = daysUntil(g.deadline);
      return {
        goal: g,
        type: "deadline",
        message:
          days === 0
            ? `"${g.title}" is due today`
            : `"${g.title}" due in ${days} days`,
      };
    }),
    ...nearComplete.map((g) => ({
      goal: g,
      type: "progress",
      message: `"${g.title}" is almost complete (${Math.round(
        (Number(g.current_amount) / Number(g.target_amount)) * 100
      )}%)`,
    })),
  ];

  if (!alerts.length) {
    return (
      <div className="bg-green-50 border border-green-200 rounded-xl p-4 flex items-center gap-3">
        <CheckCircle className="text-green-600" />
        <div>
          <h3 className="font-semibold text-green-700">On track!</h3>
          <p className="text-sm text-green-600">
            No urgent goal alerts at the moment.
          </p>
        </div>
      </div>
    );
  }

  const styles = {
    overdue: {
      bg: "bg-red-50 border-red-300",
      text: "text-red-700",
      sub: "text-red-600",
      icon: <AlertTriangle className="text-red-600" />,
    },
    deadline: {
      bg: "bg-yellow-50 border-yellow-300",
      text: "text-yellow-700",
      sub: "text-yellow-600",
      icon: <Clock className="text-yellow-600" />,
    },
    progress: {
      bg: "bg-blue-50 border-blue-300",
      text: "text-blue-700",
      sub: "text-blue-600",
      icon: <CheckCircle className="text-blue-600" />,
    },
  };

  return (
    <div className="space-y-3">
      {alerts.map(({ goal, type, message }) => {
        const s = styles[type];
        return (
          <div
            key={`${goal.id}-${type}`}
            className={`rounded-xl border p-4 flex items-start gap-3 ${s.bg}`}
          >
            {s.icon}
            <div>
              <h3 className={`font-semibold ${s.text}`}>{goal.title}</h3>
              <p className={s.sub}>{message}</p>
            </div>
          </div>
        );
      })}
    </div>
  );
}
