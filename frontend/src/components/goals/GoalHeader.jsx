import { Target, Plus } from "lucide-react";

export default function GoalHeader({ onAdd }) {
  return (
    <div className="bg-white dark:bg-gray-900 rounded-3xl border border-gray-200 dark:border-gray-700 shadow-sm p-8">

      {/* Breadcrumb */}

      <p className="text-sm text-gray-500">
        Dashboard / Goals
      </p>

      {/* Header */}

      <div className="mt-5 flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">

        <div className="flex items-start gap-5">

          <div className="h-16 w-16 rounded-2xl bg-green-100 flex items-center justify-center">
            <Target
              size={30}
              className="text-green-600"
            />
          </div>

          <div>

            <h1 className="text-4xl font-bold text-gray-900 dark:text-white">
              Savings Goals
            </h1>

            <p className="mt-2 text-gray-500 max-w-xl">
              Create savings goals, monitor your progress, and stay on
              track to achieve your financial milestones.
            </p>

          </div>

        </div>

        <button
          onClick={onAdd}
          className="
            inline-flex
            items-center
            gap-2
            rounded-2xl
            bg-blue-600
            px-6
            py-3
            font-semibold
            text-white
            shadow-md
            transition
            hover:bg-blue-700
          "
        >
          <Plus size={20} />

          Add Goal
        </button>

      </div>

    </div>
  );
}