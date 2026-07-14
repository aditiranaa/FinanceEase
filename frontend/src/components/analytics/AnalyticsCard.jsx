export default function AnalyticsCard({
  title,
  value,
  subtitle,
  icon: Icon,
  iconColor = "text-blue-600",
  iconBg = "bg-blue-100 dark:bg-blue-900/30",
}) {
  return (
    <div
      className="
        rounded-2xl
        border
        border-gray-200
        dark:border-gray-700
        bg-white
        dark:bg-gray-900
        p-5
        shadow-sm
        transition
        hover:-translate-y-0.5
        hover:shadow-md
      "
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs uppercase tracking-wider text-gray-500">
            {title}
          </p>

          <h2 className="mt-2 text-lg font-bold text-gray-900 dark:text-white">
            {value}
          </h2>

          {subtitle && (
            <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
              {subtitle}
            </p>
          )}
        </div>

        <div
          className={`
            flex
            h-12
            w-12
            items-center
            justify-center
            rounded-2xl
            ${iconBg}
          `}
        >
          <Icon
            size={22}
            className={iconColor}
          />
        </div>
      </div>
    </div>
  );
}