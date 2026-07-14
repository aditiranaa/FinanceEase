export default function AnalyticsSkeleton() {
  return (
    <div className="space-y-4 animate-pulse">
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {[1, 2, 3, 4].map((item) => (
          <div
            key={item}
            className="
              rounded-2xl
              border
              border-gray-200
              dark:border-gray-700
              bg-white
              dark:bg-gray-900
              p-5
            "
          >
            <div className="flex items-center justify-between">
              <div className="space-y-3">
                <div className="h-3 w-20 rounded bg-gray-200 dark:bg-gray-700" />
                <div className="h-7 w-28 rounded bg-gray-200 dark:bg-gray-700" />
                <div className="h-3 w-16 rounded bg-gray-200 dark:bg-gray-700" />
              </div>

              <div className="h-12 w-12 rounded-2xl bg-gray-200 dark:bg-gray-700" />
            </div>
          </div>
        ))}
      </div>

      <div className="h-[260px] rounded-2xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900" />

      <div className="grid gap-4 xl:grid-cols-2">
        <div className="h-[360px] rounded-2xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900" />
        <div className="h-[360px] rounded-2xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900" />
      </div>

      <div className="h-[320px] rounded-2xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900" />
    </div>
  );
}