export default function GoalProgress({
  current,
  target,
  completed,
}) {
  const percentage =
    target === 0
      ? 0
      : Math.min(
          100,
          Math.round((current / target) * 100)
        );

  const progress = completed ? 100 : percentage;

  const radius = 42;
  const stroke = 8;

  const normalizedRadius =
    radius - stroke * 0.5;

  const circumference =
    normalizedRadius * 2 * Math.PI;

  const strokeDashoffset =
    circumference -
    (progress / 100) * circumference;

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
    <div className="flex flex-col items-center">

      <svg
        width="110"
        height="110"
      >
        {/* Background */}

        <circle
          stroke="#e5e7eb"
          fill="transparent"
          strokeWidth={stroke}
          r={normalizedRadius}
          cx="55"
          cy="55"
        />

        {/* Progress */}

        <circle
          stroke={color}
          fill="transparent"
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={`${circumference} ${circumference}`}
          strokeDashoffset={strokeDashoffset}
          r={normalizedRadius}
          cx="55"
          cy="55"
          transform="rotate(-90 55 55)"
          style={{
            transition:
              "stroke-dashoffset .6s ease",
          }}
        />

        {/* Percentage */}

        <text
          x="55"
          y="55"
          textAnchor="middle"
          dy="8"
          className="fill-gray-900 font-bold text-xl"
        >
          {progress}%
        </text>
      </svg>

      <p className="mt-2 text-sm text-gray-500">
        Goal Progress
      </p>

    </div>
  );
}