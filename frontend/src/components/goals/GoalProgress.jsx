export default function GoalProgress({
  current = 0,
  target = 0,
  completed = false,
  size = 84,
}) {
  const percentage =
    target > 0
      ? Math.min(
          100,
          Math.round((Number(current) / Number(target)) * 100)
        )
      : 0;

  const progress = completed ? 100 : percentage;

  const stroke = 7;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;

  const strokeDashoffset =
    circumference - (progress / 100) * circumference;

  const color = completed
    ? "#16a34a"
    : progress >= 80
    ? "#16a34a"
    : progress >= 50
    ? "#2563eb"
    : progress >= 25
    ? "#f59e0b"
    : "#ef4444";

  return (
    <div className="relative flex items-center justify-center">
      <svg
        width={size}
        height={size}
        className="-rotate-90"
      >
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth={stroke}
          className="text-gray-200 dark:text-gray-700"
        />

        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          style={{
            transition:
              "stroke-dashoffset 0.6s ease, stroke 0.3s ease",
          }}
        />
      </svg>

      <div className="absolute flex flex-col items-center justify-center">
        <span className="text-lg font-bold text-gray-900 dark:text-white">
          {progress}%
        </span>

        <span className="text-[10px] uppercase tracking-wide text-gray-400">
          {completed ? "Done" : "Saved"}
        </span>
      </div>
    </div>
  );
}