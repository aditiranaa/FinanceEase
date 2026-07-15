const STATUS_STYLES = {
  good: {
    bar: "bg-emerald-500",
    text: "text-emerald-600",
  },
  warning: {
    bar: "bg-amber-400",
    text: "text-amber-500",
  },
  over: {
    bar: "bg-red-500",
    text: "text-red-500",
  },
};

export default function BudgetProgress({
  percentUsed,
  status,
}) {
  const styles =
    STATUS_STYLES[status] || STATUS_STYLES.good;

  const progress = Math.min(
    Math.max(percentUsed, 0),
    100
  );

  return (
    <div className="w-full">
      <div className="mb-3 flex items-center justify-between">
        <span
          className={`text-base font-semibold ${styles.text}`}
        >
          {percentUsed}% of budget used
        </span>

        <span className="text-sm text-gray-500">
          {percentUsed >= 100
            ? "Limit reached"
            : `${100 - percentUsed}% remaining`}
        </span>
      </div>

      <div className="h-3 w-full overflow-hidden rounded-full bg-gray-200">
        <div
          className={`h-full rounded-full transition-all duration-500 ease-out ${styles.bar}`}
          style={{
            width: `${progress}%`,
          }}
        />
      </div>
    </div>
  );
}