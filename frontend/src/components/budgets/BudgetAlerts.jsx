import { AlertTriangle, CheckCircle } from "lucide-react";

export default function BudgetAlerts({ budgets = [] }) {
  const alerts = budgets.filter((budget) => {
    const limit = Number(budget.limit || 0);
    const spent = Number(budget.spent || 0);

    if (limit <= 0) return false;

    return (spent / limit) * 100 >= 80;
  });

  if (alerts.length === 0) {
    return (
      <div className="flex items-start gap-4 rounded-2xl border border-emerald-200 bg-emerald-50 px-6 py-5 shadow-sm">
        <CheckCircle className="mt-0.5 h-6 w-6 flex-shrink-0 text-emerald-600" />

        <div>
          <h3 className="text-base font-semibold text-emerald-700">
            Great job!
          </h3>

          <p className="mt-1 text-sm text-emerald-600">
            All budgets are within a healthy spending range.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {alerts.map((budget) => {
        const percent = Math.round(
          (Number(budget.spent) / Number(budget.limit)) * 100
        );

        const exceeded = percent >= 100;

        return (
          <div
            key={budget.id}
            className={`rounded-2xl border px-6 py-5 shadow-sm ${
              exceeded
                ? "border-red-200 bg-red-50"
                : "border-amber-200 bg-amber-50"
            }`}
          >
            <div className="flex items-start gap-4">
              <AlertTriangle
                className={`mt-0.5 h-6 w-6 flex-shrink-0 ${
                  exceeded
                    ? "text-red-600"
                    : "text-amber-500"
                }`}
              />

              <div>
                <h3
                  className={`text-base font-semibold ${
                    exceeded
                      ? "text-red-700"
                      : "text-amber-700"
                  }`}
                >
                  {budget.category}
                </h3>

                <p
                  className={`mt-1 text-sm ${
                    exceeded
                      ? "text-red-600"
                      : "text-amber-600"
                  }`}
                >
                  {exceeded
                    ? `Budget exceeded by ${percent - 100}%`
                    : `${percent}% of budget used`}
                </p>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}