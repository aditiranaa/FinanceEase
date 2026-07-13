import { Target } from "lucide-react";
import GoalCard from "./GoalCard";

function EmptyState() {
  return (
    <div
      className="
        rounded-3xl
        border
        border-dashed
        border-gray-300
        dark:border-gray-700
        bg-white
        dark:bg-gray-900
        px-8
        py-20
        text-center
      "
    >
      <div
        className="
          mx-auto
          flex
          h-20
          w-20
          items-center
          justify-center
          rounded-full
          bg-blue-50
          dark:bg-blue-950/30
        "
      >
        <Target
          size={40}
          className="text-blue-600"
        />
      </div>

      <h2
        className="
          mt-6
          text-3xl
          font-bold
          text-gray-900
          dark:text-white
        "
      >
        No Goals Yet
      </h2>

      <p
        className="
          mx-auto
          mt-3
          max-w-md
          text-gray-500
          dark:text-gray-400
        "
      >
        Start your financial journey by creating your first savings goal.
      </p>
    </div>
  );
}

export default function GoalGrid({
  goals = [],
  onEdit,
  onDelete,
  onComplete,
}) {
  if (!goals.length) {
    return <EmptyState />;
  }

  return (
    <div className="grid gap-6 lg:grid-cols-2 xl:grid-cols-3">
      {goals.map((goal) => (
        <GoalCard
          key={goal.id}
          goal={goal}
          onEdit={onEdit}
          onDelete={onDelete}
          onComplete={onComplete}
        />
      ))}
    </div>
  );
}