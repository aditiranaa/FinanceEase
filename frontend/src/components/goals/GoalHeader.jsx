import { CalendarDays, Target } from "lucide-react";

export default function GoalHeader({
  totalGoals = 0,
  completedGoals = 0,
}) {
  return (
    <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
      <div className="flex items-start gap-4">
        <div
          className="
            flex
            h-14
            w-14
            items-center
            justify-center
            rounded-2xl
            bg-blue-100
            dark:bg-blue-900/30
          "
        >
          <Target
            size={28}
            className="text-blue-600"
          />
        </div>

        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
            Savings Goals
          </h1>

          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Track your progress and stay on course toward every financial milestone.
          </p>

          <div className="mt-3 flex flex-wrap gap-2">
            <span
              className="
                rounded-full
                bg-blue-50
                dark:bg-blue-900/30
                px-3
                py-1
                text-xs
                font-medium
                text-blue-700
                dark:text-blue-300
              "
            >
              {totalGoals} Total Goal{totalGoals === 1 ? "" : "s"}
            </span>

            <span
              className="
                rounded-full
                bg-green-50
                dark:bg-green-900/30
                px-3
                py-1
                text-xs
                font-medium
                text-green-700
                dark:text-green-300
              "
            >
              {completedGoals} Completed
            </span>
          </div>
        </div>
      </div>

      <div
        className="
          inline-flex
          items-center
          gap-2
          self-start
          rounded-xl
          border
          border-gray-200
          dark:border-gray-700
          bg-white
          dark:bg-gray-900
          px-4
          py-2.5
          text-sm
          text-gray-600
          dark:text-gray-300
        "
      >
        <CalendarDays size={17} />
        Current Month
      </div>
    </div>
  );
}