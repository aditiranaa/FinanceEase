import { useEffect, useState } from "react";

import {
  getNotifications,
  markAsRead,
  deleteNotification,
} from "../services/notificationService";

export default function useNotifications() {
  const [notifications, setNotifications] =
    useState([]);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState("");

  const loadNotifications = async () => {
    try {
      setLoading(true);

      const data =
        await getNotifications();

      setNotifications(data);
    } catch (err) {
      console.error(err);

      setError(
        "Failed to load notifications."
      );
    } finally {
      setLoading(false);
    }
  };

  const readNotification = async (id) => {
    await markAsRead(id);

    setNotifications((prev) =>
      prev.map((n) =>
        n.id === id
          ? { ...n, is_read: true }
          : n
      )
    );
  };

  const removeNotification = async (id) => {
    await deleteNotification(id);

    setNotifications((prev) =>
      prev.filter((n) => n.id !== id)
    );
  };

  useEffect(() => {
    loadNotifications();
  }, []);

  return {
    notifications,
    loading,
    error,
    readNotification,
    removeNotification,
    refresh: loadNotifications,
  };
}