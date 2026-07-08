import { useEffect, useState } from "react";

import {
  getSubscriptions,
  createSubscription,
  updateSubscription,
  deleteSubscription,
} from "../services/subscriptionService";

export default function useSubscriptions() {
  const [subscriptions, setSubscriptions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadSubscriptions = async () => {
    try {
      setLoading(true);

      const data = await getSubscriptions();

      setSubscriptions(data);
    } catch (err) {
      console.error(err);

      setError("Failed to load subscriptions.");
    } finally {
      setLoading(false);
    }
  };

  const addSubscription = async (subscription) => {
    const created = await createSubscription(subscription);

    setSubscriptions((prev) => [...prev, created]);
  };

  const editSubscription = async (id, subscription) => {
    await updateSubscription(id, subscription);

    setSubscriptions((prev) =>
      prev.map((item) =>
        item.id === id
          ? { ...item, ...subscription }
          : item
      )
    );
  };

  const removeSubscription = async (id) => {
    await deleteSubscription(id);

    setSubscriptions((prev) =>
      prev.filter((item) => item.id !== id)
    );
  };

  useEffect(() => {
    loadSubscriptions();
  }, []);

  return {
    subscriptions,
    loading,
    error,
    addSubscription,
    editSubscription,
    removeSubscription,
    refresh: loadSubscriptions,
  };
}