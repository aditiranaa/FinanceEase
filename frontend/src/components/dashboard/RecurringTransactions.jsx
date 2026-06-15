import {
  useEffect,
  useState,
} from "react";

import {
  getSubscriptions,
  createSubscription,
} from "../../api/authApi";

const RecurringTransactions = () => {

  const [formData, setFormData] =
    useState({
      name: "",
      next_due: "",
    });

  const [subscriptions, setSubscriptions] =
    useState([]);

  const handleChange = (e) => {

    setFormData({
      ...formData,
      [e.target.name]:
        e.target.value,
    });

  };

  const fetchSubscriptions =
    async () => {

      try {

        const data =
          await getSubscriptions();

        setSubscriptions(data);

      } catch (error) {

        console.log(error);

      }

    };

  useEffect(() => {

    fetchSubscriptions();

  }, []);

  const handleSubmit =
    async (e) => {

      e.preventDefault();

      try {

        await createSubscription(
          formData
        );

        await fetchSubscriptions();

        setFormData({
          name: "",
          next_due: "",
        });

      } catch (error) {

        console.log(error);

      }

    };

  return (

    <div
      className="
        bg-white
        p-6
        rounded-2xl
        shadow-sm
        mt-8
      "
    >

      <h2
        className="
          text-2xl
          font-bold
          mb-4
        "
      >
        Recurring Transactions
      </h2>

      <form
  onSubmit={handleSubmit}
  className="space-y-4"
>

  <input
    type="text"
    name="name"
    placeholder="Netflix"
    value={formData.name}
    onChange={handleChange}
    className="
      w-full
      border
      p-3
      rounded-lg
    "
  />

  <input
    type="date"
    name="next_due"
    value={formData.next_due}
    onChange={handleChange}
    className="
      w-full
      border
      p-3
      rounded-lg
    "
  />

  <button
    type="submit"
    className="
      bg-indigo-500
      text-white
      px-5
      py-3
      rounded-lg
      hover:bg-indigo-600
    "
  >
    Add Subscription
  </button>

</form>

<div className="mt-6 space-y-3">

  {subscriptions.length === 0 ? (

    <p className="text-gray-400">
      No recurring transactions yet
    </p>

  ) : (

    subscriptions.map(
      (subscription) => (

        <div
          key={subscription.id}
          className="
            bg-gray-50
            p-4
            rounded-xl
          "
        >

          <h3
            className="
              font-semibold
              text-gray-800
            "
          >
            {subscription.name}
          </h3>

          <p
            className="
              text-gray-500
              mt-1
            "
          >
            Next Due:
            {" "}
            {subscription.next_due}
          </p>

        </div>

      )
    )

  )}

</div>

    </div>

  );

};

export default RecurringTransactions;