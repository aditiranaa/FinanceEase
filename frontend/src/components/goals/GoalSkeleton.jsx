export default function GoalSkeleton() {
  return (
    <div
      className="
        animate-pulse
        rounded-2xl
        border
        border-gray-200
        dark:border-gray-700
        bg-white
        dark:bg-gray-900
        p-4
        shadow-sm
      "
    >
      <div className="flex items-start justify-between">
        <div className="space-y-3">
          <div className="h-6 w-24 rounded-full bg-gray-200 dark:bg-gray-700" />

          <div className="h-8 w-44 rounded-lg bg-gray-200 dark:bg-gray-700" />

          <div className="h-5 w-28 rounded-full bg-gray-200 dark:bg-gray-700" />
        </div>

        <div className="h-10 w-10 rounded-xl bg-gray-200 dark:bg-gray-700" />
      </div>

      <div className="my-8 flex justify-center">
        <div className="h-24 w-24 rounded-full bg-gray-200 dark:bg-gray-700" />
      </div>

      <div className="mb-5">
        <div className="mb-2 h-3 w-full rounded-full bg-gray-200 dark:bg-gray-700" />

        <div className="h-2 w-full rounded-full bg-gray-200 dark:bg-gray-700" />
      </div>

      <div className="grid grid-cols-3 gap-3">
        {[1, 2, 3].map((item) => (
          <div
            key={item}
            className="rounded-xl bg-gray-100 dark:bg-gray-800 p-3"
          >
            <div className="h-3 w-12 rounded bg-gray-200 dark:bg-gray-700" />

            <div className="mt-3 h-5 w-16 rounded bg-gray-200 dark:bg-gray-700" />
          </div>
        ))}
      </div>

      <div className="mt-6 border-t border-gray-200 dark:border-gray-700 pt-4">
        <div className="h-4 w-40 rounded bg-gray-200 dark:bg-gray-700" />
      </div>
    </div>
  );
}