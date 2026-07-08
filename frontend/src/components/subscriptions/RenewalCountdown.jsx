import { CalendarClock } from "lucide-react";

export default function RenewalCountdown({
  subscriptions,
}) {
  const upcoming = subscriptions
    .filter((s) => s.active)
    .sort(
      (a, b) =>
        new Date(a.next_due) -
        new Date(b.next_due)
    )
    .slice(0, 5);

  if (upcoming.length === 0) return null;

  return (
    <div className="bg-white dark:bg-gray-900 rounded-xl shadow-md p-6">

      <div className="flex items-center gap-2 mb-5">
        <CalendarClock className="text-blue-600" />

        <h2 className="text-xl font-bold">
          Upcoming Renewals
        </h2>
      </div>

      <div className="space-y-4">

        {upcoming.map((sub) => {
          const days = Math.ceil(
            (new Date(sub.next_due) -
              new Date()) /
              (1000 * 60 * 60 * 24)
          );

          return (
            <div
              key={sub.id}
              className="flex justify-between border-b pb-3"
            >
              <div>

                <h3 className="font-semibold">
                  {sub.name}
                </h3>

                <p className="text-sm text-gray-500">
                  {sub.next_due}
                </p>

              </div>

              <span
                className={`font-medium ${
                  days <= 3
                    ? "text-red-600"
                    : "text-blue-600"
                }`}
              >
                {days} days
              </span>

            </div>
          );
        })}

      </div>

    </div>
  );
}