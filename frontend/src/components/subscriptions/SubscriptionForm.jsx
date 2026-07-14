import { useEffect, useState } from "react";

const initialState = {
  name: "",
  category: "Entertainment",
  amount: "",
  frequency: "Monthly",
  next_due: "",
  active: true,
};

const categories = [
  "Entertainment",
  "Music",
  "Cloud",
  "Education",
  "Fitness",
  "Utilities",
  "Software",
  "Other",
];

const frequencies = [
  "Monthly",
  "Quarterly",
  "Yearly",
];

export default function SubscriptionForm({
  editingSubscription,
  onSubmit,
  onCancel,
}) {
  const [form, setForm] =
    useState(initialState);

  useEffect(() => {
    if (editingSubscription) {
      setForm({
        ...editingSubscription,
        next_due: editingSubscription.next_due
          ? editingSubscription.next_due.slice(0, 10)
          : "",
      });
    } else {
      setForm(initialState);
    }
  }, [editingSubscription]);

  const handleChange = (e) => {
    const { name, value, type, checked } =
      e.target;

    setForm({
      ...form,
      [name]:
        type === "checkbox"
          ? checked
          : value,
    });
  };

  const submit = (e) => {
    e.preventDefault();

    onSubmit(form);

    setForm(initialState);
  };

  return (
    <form
      onSubmit={submit}
      className="bg-white dark:bg-gray-900 rounded-xl shadow-md p-4 space-y-4"
    >
      <h2 className="text-lg font-bold">
        {editingSubscription
          ? "Edit Subscription"
          : "Add Subscription"}
      </h2>

      <input
        className="w-full border rounded-lg p-3"
        placeholder="Subscription Name"
        name="name"
        value={form.name}
        onChange={handleChange}
        required
      />

      <select
        className="w-full border rounded-lg p-3"
        name="category"
        value={form.category}
        onChange={handleChange}
      >
        {categories.map((cat) => (
          <option
            key={cat}
            value={cat}
          >
            {cat}
          </option>
        ))}
      </select>

      <input
        className="w-full border rounded-lg p-3"
        type="number"
        placeholder="Monthly Cost"
        name="amount"
        value={form.amount}
        onChange={handleChange}
        required
      />

      <select
        className="w-full border rounded-lg p-3"
        name="frequency"
        value={form.frequency}
        onChange={handleChange}
      >
        {frequencies.map((item) => (
          <option
            key={item}
            value={item}
          >
            {item}
          </option>
        ))}
      </select>

      <input
        className="w-full border rounded-lg p-3"
        type="date"
        name="next_due"
        value={form.next_due}
        onChange={handleChange}
      />

      <label className="flex items-center gap-3">
        <input
          type="checkbox"
          name="active"
          checked={form.active}
          onChange={handleChange}
        />

        Active Subscription
      </label>

      <div className="flex gap-3">

        <button className="px-5 py-2 rounded-lg bg-blue-600 text-white">
          {editingSubscription
            ? "Update"
            : "Save"}
        </button>

        {editingSubscription && (
          <button
            type="button"
            onClick={onCancel}
            className="px-5 py-2 rounded-lg bg-gray-200"
          >
            Cancel
          </button>
        )}

      </div>

    </form>
  );
}