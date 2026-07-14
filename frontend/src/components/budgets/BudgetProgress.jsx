export default function BudgetProgress({
  spent,
  limit,
}) {
  const percentage =
    limit === 0
      ? 0
      : Math.min(
          100,
          Math.round((spent / limit) * 100)
        );

  const color =
    percentage >= 100
      ? "bg-red-600"
      : percentage >= 80
      ? "bg-yellow-500"
      : "bg-green-600";

  return (
    <div>

      <div className="flex justify-between text-xs mb-2">

        <span>
          Budget Usage
        </span>

        <span>
          {percentage}%
        </span>

      </div>

      <div className="w-full h-3 bg-gray-200 rounded-full overflow-hidden">

        <div
          className={`h-full transition-all duration-500 ${color}`}
          style={{
            width: `${percentage}%`,
          }}
        />

      </div>

    </div>
  );
}