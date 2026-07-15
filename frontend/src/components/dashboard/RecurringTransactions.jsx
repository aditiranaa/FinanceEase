import {
  useEffect,
  useState,
} from "react";

import {
  CalendarClock,
  Plus,
  Repeat,
  CreditCard,
} from "lucide-react";

import {
  getSubscriptions,
  createSubscription,
} from "../../api/authApi";

export default function RecurringTransactions() {
  const [formData, setFormData] =
    useState({
      name: "",
      next_due: "",
    });

  const [subscriptions, setSubscriptions] =
    useState([]);

  const [loading, setLoading] =
    useState(false);

  const inputClass =
    "h-12 w-full rounded-xl border border-gray-200 bg-gray-50 px-4 outline-none transition focus:border-indigo-500 focus:bg-white focus:ring-4 focus:ring-indigo-100";

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
        setLoading(true);

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
      } finally {
        setLoading(false);
      }
    };

  return (
    <section className="rounded-3xl border border-gray-200 bg-white p-7 shadow-sm">
      <div className="mb-8 flex items-center gap-4">
        <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-indigo-100">
          <Repeat
            size={28}
            className="text-indigo-600"
          />
        </div>

        <div>
          <h2 className="text-2xl font-bold text-gray-900">
            Recurring Payments
          </h2>

          <p className="mt-1 text-sm text-gray-500">
            Track subscriptions and upcoming
            recurring expenses.
          </p>
        </div>
      </div>

      {/* Add Subscription */}

      <form
        onSubmit={handleSubmit}
        className="rounded-2xl border border-gray-100 bg-gray-50 p-5"
      >
        <div className="grid gap-4">
          <input
            type="text"
            name="name"
            placeholder="Netflix"
            value={formData.name}
            onChange={handleChange}
            className={inputClass}
          />

          <input
            type="date"
            name="next_due"
            value={formData.next_due}
            onChange={handleChange}
            className={inputClass}
          />

          <button
            type="submit"
            disabled={loading}
            className="flex h-12 items-center justify-center gap-2 rounded-xl bg-indigo-600 font-semibold text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60"
          >
            <Plus size={18} />

            {loading
              ? "Adding..."
              : "Add Subscription"}
          </button>
        </div>
      </form>

      {/* Subscription List */}

      <div className="mt-8 space-y-4">
        {subscriptions.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-gray-200 bg-gray-50 py-12 text-center">
            <CreditCard
              size={42}
              className="mx-auto mb-4 text-gray-300"
            />

            <h3 className="text-lg font-semibold text-gray-800">
              No Recurring Payments
            </h3>

            <p className="mt-2 text-sm text-gray-500">
              Add subscriptions like Netflix,
              Spotify or your monthly bills.
            </p>
          </div>
        ) : (
          subscriptions.map(
            (subscription) => (
              <div
                key={subscription.id}
                className="flex items-center justify-between rounded-2xl border border-gray-100 bg-gray-50 p-5 transition hover:border-indigo-200 hover:bg-white"
              >
                <div className="flex items-center gap-4">
                  <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-indigo-100">
                    <Repeat
                      size={22}
                      className="text-indigo-600"
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold text-gray-900">
                      {subscription.name}
                    </h3>

                    <div className="mt-1 flex items-center gap-2 text-sm text-gray-500">
                      <CalendarClock size={15} />

                      <span>
                        Due on{" "}
                        {new Date(
                          subscription.next_due
                        ).toLocaleDateString(
                          "en-IN",
                          {
                            day: "numeric",
                            month: "short",
                            year: "numeric",
                          }
                        )}
                      </span>
                    </div>
                  </div>
                </div>

                <span className="rounded-full bg-indigo-100 px-3 py-1 text-xs font-semibold text-indigo-700">
                  Active
                </span>
              </div>
            )
          )
        )}
      </div>
    </section>
  );
}