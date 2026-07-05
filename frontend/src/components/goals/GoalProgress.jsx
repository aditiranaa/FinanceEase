export default function GoalProgress({ current, target, completed }) {
  const percentage =
    target === 0
      ? 0
      : Math.min(100, Math.round((current / target) * 100));

  const color = completed
    ? "bg-green-600"
    : percentage >= 100
    ? "bg-green-600"
    : percentage >= 75
    ? "bg-blue-500"
    : percentage >= 50
    ? "bg-yellow-500"
    : "bg-green-500";

  return (
    <div>
      <div className="flex justify-between text-sm mb-2">
        <span>Progress</span>
        <span>{completed ? "100" : percentage}%</span>
      </div>

      <div className="w-full h-3 bg-gray-200 rounded-full overflow-hidden">
        <div
          className={`h-full transition-all duration-500 ${color}`}
          style={{ width: `${completed ? 100 : percentage}%` }}
        />
      </div>
    </div>
  );
}
