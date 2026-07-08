import {
  Bell,
  CheckCircle2,
  Trash2,
} from "lucide-react";

export default function NotificationCard({
  notification,
  onRead,
  onDelete,
}) {
  return (
    <div
      className={`rounded-xl shadow border p-5 transition ${
        notification.is_read
          ? "bg-gray-50 border-gray-200"
          : "bg-blue-50 border-blue-300"
      }`}
    >
      <div className="flex justify-between">

        <div className="flex gap-3">

          <Bell className="text-blue-600 mt-1" />

          <div>

            <h3 className="font-semibold">
              {notification.title}
            </h3>

            <p className="text-gray-600 mt-1">
              {notification.message}
            </p>

            <p className="text-xs text-gray-400 mt-3">
              {new Date(
                notification.created_at
              ).toLocaleString()}
            </p>

          </div>

        </div>

        <div className="flex gap-2">

          {!notification.is_read && (
            <button
              onClick={() =>
                onRead(notification.id)
              }
              className="p-2 rounded-lg bg-green-100 hover:bg-green-200 text-green-600"
            >
              <CheckCircle2 size={18} />
            </button>
          )}

          <button
            onClick={() =>
              onDelete(notification.id)
            }
            className="p-2 rounded-lg bg-red-100 hover:bg-red-200 text-red-600"
          >
            <Trash2 size={18} />
          </button>

        </div>

      </div>

    </div>
  );
}