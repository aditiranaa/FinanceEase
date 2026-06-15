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

      {/* form and list go here */}

    </div>

  );

};

export default RecurringTransactions;