import Navbar from "../../components/layout/Navbar";
import Sidebar from "../../components/layout/Sidebar";

import useSubscriptions from "../../hooks/useSubscriptions";

import SubscriptionManager from "./SubscriptionManager";

export default function Subscriptions() {
  const {
    subscriptions,
    loading,
    error,
    addSubscription,
    editSubscription,
    removeSubscription,
  } = useSubscriptions();

  if (loading) {
    return (
      <div className="flex justify-center items-center h-screen">
        <p className="text-lg">
          Loading subscriptions...
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
              Subscription Tracker
            </h1>

            <p className="text-gray-500">
              Manage recurring subscriptions,
              upcoming renewals and monthly costs.
            </p>
          </div>

          <SubscriptionManager
            subscriptions={subscriptions}
            addSubscription={addSubscription}
            editSubscription={editSubscription}
            removeSubscription={removeSubscription}
          />

        </div>
      </div>
    </div>
  );
}