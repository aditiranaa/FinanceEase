import { useState } from "react";

import NotificationOverview from "../../components/notifications/NotificationOverview";
import NotificationFilters from "../../components/notifications/NotificationFilters";
import NotificationList from "../../components/notifications/NotificationList";

export default function NotificationManager({
  notifications,
  readNotification,
  removeNotification,
}) {
  const [filter, setFilter] =
    useState("all");

  const filtered = notifications.filter(
    (notification) => {
      if (filter === "read")
        return notification.is_read;

      if (filter === "unread")
        return !notification.is_read;

      return true;
    }
  );

  return (
    <div className="space-y-8">

      <NotificationOverview
        notifications={notifications}
      />

      <NotificationFilters
        onFilter={setFilter}
      />

      <NotificationList
        notifications={filtered}
        onRead={readNotification}
        onDelete={removeNotification}
      />

    </div>
  );
}