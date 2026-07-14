import { BarChart3 } from "lucide-react";

export default function EmptyAnalytics() {
  return (
    <div
      className="
        rounded-2xl
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
          dark:bg-blue-900/30
        "
      >
        <BarChart3
          size={40}
          className="text-blue-600"
        />
      </div>

      <h2 className="mt-6 text-3xl font-bold text-gray-900 dark:text-white">
        No Analytics Available
      </h2>

      <p className="mx-auto mt-3 max-w-md text-gray-500 dark:text-gray-400">
        Add income and expense transactions to generate reports and financial insights.
      </p>
    </div>
  );
}