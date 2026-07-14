import { AlertTriangle, CheckCircle } from "lucide-react";

export default function BudgetAlerts({ budgets = [] }) {
  const alerts = budgets.filter((budget) => {
    const limit = Number(budget.limit);
    const spent = Number(budget.spent);

    if (limit === 0) return false;

    return (spent / limit) * 100 >= 80;
  });

  if (!alerts.length) {
    return (
      <div className="bg-green-50 border border-green-200 rounded-xl p-4 flex items-center gap-3">
        <CheckCircle className="text-green-600" />
        <div>
          <h3 className="font-semibold text-green-700">
            Great job!
          </h3>
          <p className="text-xs text-green-600">
            All budgets are within a healthy spending range.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {alerts.map((budget) => {
        const percent = Math.round(
          (Number(budget.spent) / Number(budget.limit)) * 100
        );

        const exceeded = percent >= 100;

        return (
          <div
            key={budget.id}
            className={`rounded-xl border p-4 flex items-start gap-3 ${
              exceeded
                ? "bg-red-50 border-red-300"
                : "bg-yellow-50 border-yellow-300"
            }`}
          >
            <AlertTriangle
              className={
                exceeded
                  ? "text-red-600"
                  : "text-yellow-600"
              }
            />

            <div>
              <h3
                className={`font-semibold ${
                  exceeded
                    ? "text-red-700"
                    : "text-yellow-700"
                }`}
              >
                {budget.category}
              </h3>

              <p
                className={
                  exceeded
                    ? "text-red-600"
                    : "text-yellow-600"
                }
              >
                {exceeded
                  ? `Budget exceeded by ${percent - 100}%`
                  : `${percent}% of budget used`}
              </p>
            </div>
          </div>
        );
      })}
    </div>
  );
}