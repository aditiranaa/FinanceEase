import Navbar from "../../components/layout/Navbar";
import Sidebar from "../../components/layout/Sidebar";

import useNotifications from "../../hooks/useNotifications";

import NotificationManager from "./NotificationManager";

export default function Notifications() {

  const {
    notifications,
    loading,
    error,
    readNotification,
    removeNotification,
  } = useNotifications();

  if (loading) {
    return (
      <div className="flex justify-center items-center h-screen">
        <p className="text-lg">
          Loading notifications...
        </p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex justify-center items-center h-screen text-red-600">
        {error}
      </div>
    );
  }

  return (
    <div className="flex flex-col md:flex-row">

      <Sidebar />

      <div className="flex-1 bg-gray-100 dark:bg-gray-950 min-h-screen p-6">

        <Navbar />

        <div className="mt-8 space-y-8">

          <div>

            <h1 className="text-3xl font-bold">
              Notifications
            </h1>

            <p className="text-gray-500">
              Stay updated with your budgets, goals, subscriptions and reminders.
            </p>

          </div>

          <NotificationManager
            notifications={notifications}
            readNotification={readNotification}
            removeNotification={removeNotification}
          />

        </div>

      </div>

    </div>
  );
}