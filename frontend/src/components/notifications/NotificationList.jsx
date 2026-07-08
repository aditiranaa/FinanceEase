import NotificationCard from "./NotificationCard";

export default function NotificationList({
  notifications,
  onRead,
  onDelete,
}) {
  if (notifications.length === 0) {
    return (
      <div className="bg-white dark:bg-gray-900 rounded-xl shadow p-10 text-center">
        <h2 className="text-xl font-semibold">
          No Notifications
        </h2>

        <p className="text-gray-500 mt-2">
          You're all caught up 🎉
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">

      {notifications.map((notification) => (
        <NotificationCard
          key={notification.id}
          notification={notification}
          onRead={onRead}
          onDelete={onDelete}
        />
      ))}

    </div>
  );
}