import {
  Pencil,
  Trash2,
  Calendar,
  IndianRupee,
} from "lucide-react";

const formatCurrency = (value) =>
  Number(value || 0).toLocaleString("en-IN", {
    style: "currency",
    currency: "INR",
  });

const daysLeft = (date) => {
  if (!date) return null;

  return Math.ceil(
    (new Date(date) - new Date()) /
      (1000 * 60 * 60 * 24)
  );
};

export default function SubscriptionCard({
  subscription,
  onEdit,
  onDelete,
}) {
  const days = daysLeft(subscription.next_due);

  return (
    <div className="bg-white dark:bg-gray-900 rounded-xl shadow-md border border-gray-200 dark:border-gray-800 p-6">

      <div className="flex justify-between">

        <div>

          <h2 className="text-lg font-semibold">
            {subscription.name}
          </h2>

          <p className="text-gray-500">
            {subscription.category}
          </p>

        </div>

        <div className="flex gap-2">

          <button
            onClick={() =>
              onEdit(subscription)
            }
            className="p-2 rounded-lg bg-blue-100 text-blue-600"
          >
            <Pencil size={18} />
          </button>

          <button
            onClick={() =>
              onDelete(subscription.id)
            }
            className="p-2 rounded-lg bg-red-100 text-red-600"
          >
            <Trash2 size={18} />
          </button>

        </div>

      </div>

      <div className="mt-5 space-y-2">

        <div className="flex items-center gap-2">

          <IndianRupee size={16} />

          {formatCurrency(subscription.amount)}

        </div>

        <div className="flex items-center gap-2">

          <Calendar size={16} />

          {subscription.next_due}

        </div>

        {days !== null && (
          <p className="text-sm text-blue-600">
            Renews in {days} days
          </p>
        )}

      </div>

    </div>
  );
}