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

  const radius = 34;
  const stroke = 6;

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
    <svg width="80" height="80">

      <circle
        stroke="#e5e7eb"
        fill="transparent"
        strokeWidth={stroke}
        r={normalizedRadius}
        cx="40"
        cy="40"
      />

      <circle
        stroke={color}
        fill="transparent"
        strokeWidth={stroke}
        strokeLinecap="round"
        strokeDasharray={`${circumference} ${circumference}`}
        strokeDashoffset={strokeDashoffset}
        r={normalizedRadius}
        cx="40"
        cy="40"
        transform="rotate(-90 40 40)"
      />

      <text
        x="40"
        y="44"
        textAnchor="middle"
        className="fill-gray-900 font-bold text-sm"
      >
        {progress}%
      </text>

    </svg>
  );
}