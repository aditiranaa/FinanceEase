import { useMemo } from "react";
import {
  AlertTriangle,
  Clock3,
  Trophy,
} from "lucide-react";

const DAY = 1000 * 60 * 60 * 24;

const getDaysLeft = (deadline) => {
  if (!deadline) return null;

  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const due = new Date(deadline);
  due.setHours(0, 0, 0, 0);

  return Math.ceil((due - today) / DAY);
};

function AlertCard({
  icon: Icon,
  title,
  message,
  colors,
}) {
  return (
    <div
      className={`
        rounded-2xl
        border
        p-5
        ${colors.container}
      `}
    >
      <Icon
        size={28}
        className={colors.icon}
      />

      <h3
        className={`mt-3 font-bold ${colors.title}`}
      >
        {title}
      </h3>

      <p
        className={`mt-2 text-sm ${colors.text}`}
      >
        {message}
      </p>
    </div>
  );
}

export default function GoalAlerts({
  goals = [],
}) {
  const { overdue, upcoming, completed } =
    useMemo(() => {
      const overdue = [];
      const upcoming = [];
      const completed = [];

      goals.forEach((goal) => {
        if (goal.completed) {
          completed.push(goal);
          return;
        }

        const days = getDaysLeft(goal.deadline);

        if (days === null) return;

        if (days < 0) {
          overdue.push(goal);
        } else if (days <= 7) {
          upcoming.push(goal);
        }
      });

      return {
        overdue,
        upcoming,
        completed,
      };
    }, [goals]);

  const cards = [
    overdue.length > 0 && {
      key: "overdue",
      icon: AlertTriangle,
      title: "Overdue Goals",
      message: `${overdue.length} goal${
        overdue.length > 1 ? "s have" : " has"
      } crossed ${
        overdue.length > 1
          ? "their deadlines."
          : "its deadline."
      }`,
      colors: {
        container:
          "border-red-200 bg-red-50 dark:border-red-900/50 dark:bg-red-950/30",
        icon: "text-red-600",
        title: "text-red-700 dark:text-red-300",
        text: "text-red-600 dark:text-red-400",
      },
    },

    upcoming.length > 0 && {
      key: "upcoming",
      icon: Clock3,
      title: "Upcoming Deadlines",
      message: `${upcoming.length} goal${
        upcoming.length > 1 ? "s are" : " is"
      } due within the next 7 days.`,
      colors: {
        container:
          "border-yellow-200 bg-yellow-50 dark:border-yellow-900/50 dark:bg-yellow-950/30",
        icon: "text-yellow-600",
        title: "text-yellow-700 dark:text-yellow-300",
        text: "text-yellow-700 dark:text-yellow-400",
      },
    },

    completed.length > 0 && {
      key: "completed",
      icon: Trophy,
      title: "Completed Goals",
      message: `Great job! You've completed ${completed.length} goal${
        completed.length > 1 ? "s." : "."
      }`,
      colors: {
        container:
          "border-green-200 bg-green-50 dark:border-green-900/50 dark:bg-green-950/30",
        icon: "text-green-600",
        title: "text-green-700 dark:text-green-300",
        text: "text-green-700 dark:text-green-400",
      },
    },
  ].filter(Boolean);

  if (cards.length === 0) return null;

  return (
    <div className="grid gap-4 lg:grid-cols-3">
      {cards.map((card) => (
        <AlertCard
          key={card.key}
          {...card}
        />
      ))}
    </div>
  );
}