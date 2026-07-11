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

  const radius = 46;
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
    <div className="flex items-center justify-center">

      <svg
        width="120"
        height="120"
        className="overflow-visible"
      >
        {/* Background Circle */}

        <circle
          cx="60"
          cy="60"
          r={normalizedRadius}
          stroke="#e5e7eb"
          strokeWidth={stroke}
          fill="transparent"
        />

        {/* Progress Circle */}

        <circle
          cx="60"
          cy="60"
          r={normalizedRadius}
          stroke={color}
          strokeWidth={stroke}
          fill="transparent"
          strokeLinecap="round"
          strokeDasharray={`${circumference} ${circumference}`}
          strokeDashoffset={strokeDashoffset}
          transform="rotate(-90 60 60)"
          style={{
            transition:
              "stroke-dashoffset 0.6s ease",
          }}
        />

        {/* Percentage */}

        <text
          x="60"
          y="60"
          textAnchor="middle"
          dominantBaseline="middle"
          className="fill-gray-900 font-extrabold text-2xl"
        >
          {progress}%
        </text>
      </svg>

    </div>
  );
}