import { useState } from "react";

import SubscriptionForm from "../../components/subscriptions/SubscriptionForm";
import SubscriptionCard from "../../components/subscriptions/SubscriptionCard";
import SubscriptionOverview from "../../components/subscriptions/SubscriptionOverview";
import RenewalCountdown from "../../components/subscriptions/RenewalCountdown";

export default function SubscriptionManager({
  subscriptions,
  addSubscription,
  editSubscription,
  removeSubscription,
}) {
  const [editingSubscription, setEditingSubscription] =
    useState(null);

  const handleSubmit = async (subscription) => {
    if (editingSubscription) {
      await editSubscription(
        editingSubscription.id,
        subscription
      );

      setEditingSubscription(null);
    } else {
      await addSubscription(subscription);
    }
  };

  return (
    <div className="space-y-8">

      <SubscriptionOverview
        subscriptions={subscriptions}
      />

      <RenewalCountdown
        subscriptions={subscriptions}
      />

      <SubscriptionForm
        editingSubscription={editingSubscription}
        onSubmit={handleSubmit}
        onCancel={() =>
          setEditingSubscription(null)
        }
      />

      <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-3">

        {subscriptions.map((subscription) => (
          <SubscriptionCard
            key={subscription.id}
            subscription={subscription}
            onEdit={setEditingSubscription}
            onDelete={removeSubscription}
          />
        ))}

      </div>

    </div>
  );
}