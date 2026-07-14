import BudgetProgress from "./BudgetProgress";
import {
  Pencil,
  Trash2,
  IndianRupee,
} from "lucide-react";

const formatCurrency = (amount) =>
  Number(amount || 0).toLocaleString("en-IN", {
    style: "currency",
    currency: "INR",
  });

export default function BudgetCard({
  budget,
  onEdit,
  onDelete,
}) {
  const limit = Number(budget.limit);
  const spent = Number(budget.spent);
  const remaining = limit - spent;

  return (
    <div className="bg-white dark:bg-gray-900 rounded-xl shadow-md border border-gray-200 dark:border-gray-800 p-4 transition hover:shadow-lg">

      <div className="flex items-center justify-between">

        <div>

          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            {budget.category}
          </h2>

          <p className="text-xs text-gray-500">
            {budget.month}
          </p>

        </div>

        <div className="flex gap-2">

          <button
            onClick={() => onEdit(budget)}
            className="p-2 rounded-lg bg-blue-100 hover:bg-blue-200 text-blue-600"
          >
            <Pencil size={18} />
          </button>

          <button
            onClick={() => onDelete(budget.id)}
            className="p-2 rounded-lg bg-red-100 hover:bg-red-200 text-red-600"
          >
            <Trash2 size={18} />
          </button>

        </div>

      </div>

      <div className="mt-5">

        <BudgetProgress
          spent={spent}
          limit={limit}
        />

      </div>

      <div className="grid grid-cols-3 gap-4 mt-6">

        <div>

          <p className="text-xs text-gray-500">
            Budget
          </p>

          <div className="flex items-center gap-1 font-semibold">

            <IndianRupee size={16} />

            {formatCurrency(limit)}

          </div>

        </div>

        <div>

          <p className="text-xs text-gray-500">
            Spent
          </p>

          <div className="flex items-center gap-1 font-semibold text-red-600">

            <IndianRupee size={16} />

            {formatCurrency(spent)}

          </div>

        </div>

        <div>

          <p className="text-xs text-gray-500">
            Remaining
          </p>

          <div
            className={`flex items-center gap-1 font-semibold ${
              remaining >= 0
                ? "text-green-600"
                : "text-red-600"
            }`}
          >
            <IndianRupee size={16} />

            {formatCurrency(remaining)}

          </div>

        </div>

      </div>

    </div>
  );
}