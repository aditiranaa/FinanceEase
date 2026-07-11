import { useEffect, useState } from "react";

const CATEGORIES = [
  "General",
  "Emergency",
  "Vacation",
  "Home",
  "Education",
  "Vehicle",
  "Retirement",
];

const initialState = {
  title: "",
  category: "General",
  target_amount: "",
  current_amount: "",
  deadline: "",
};

export default function GoalForm({
  editingGoal,
  onSubmit,
  onCancel,
}) {
  const [form, setForm] =
    useState(initialState);

  useEffect(() => {
    if (editingGoal) {
      setForm({
        ...editingGoal,
        deadline: editingGoal.deadline
          ? editingGoal.deadline.slice(0, 10)
          : "",
      });
    } else {
      setForm(initialState);
    }
  }, [editingGoal]);

  const handleChange = (e) =>
    setForm({
      ...form,
      [e.target.name]:
        e.target.value,
    });

  const handleSubmit = (e) => {
    e.preventDefault();

    onSubmit(form);

    setForm(initialState);
  };

  return (
    <form
      onSubmit={handleSubmit}
      className="space-y-6"
    >

      <div>

        <label className="block text-sm font-semibold mb-2">
          Goal Title
        </label>

        <input
          name="title"
          value={form.title}
          onChange={handleChange}
          placeholder="MacBook Pro"
          required
          className="w-full rounded-xl border px-4 py-3 focus:ring-2 focus:ring-blue-500 outline-none"
        />

      </div>

      <div className="grid md:grid-cols-2 gap-5">

        <div>

          <label className="block text-sm font-semibold mb-2">
            Category
          </label>

          <select
            name="category"
            value={form.category}
            onChange={handleChange}
            className="w-full rounded-xl border px-4 py-3"
          >
            {CATEGORIES.map((c) => (
              <option
                key={c}
                value={c}
              >
                {c}
              </option>
            ))}
          </select>

        </div>

        <div>

          <label className="block text-sm font-semibold mb-2">
            Deadline
          </label>

          <input
            type="date"
            name="deadline"
            value={form.deadline}
            onChange={handleChange}
            className="w-full rounded-xl border px-4 py-3"
          />

        </div>

      </div>

      <div className="grid md:grid-cols-2 gap-5">

        <div>

          <label className="block text-sm font-semibold mb-2">
            Target Amount
          </label>

          <input
            type="number"
            name="target_amount"
            value={form.target_amount}
            onChange={handleChange}
            className="w-full rounded-xl border px-4 py-3"
            required
          />

        </div>

        <div>

          <label className="block text-sm font-semibold mb-2">
            Current Saved
          </label>

          <input
            type="number"
            name="current_amount"
            value={form.current_amount}
            onChange={handleChange}
            className="w-full rounded-xl border px-4 py-3"
          />

        </div>

      </div>

      <div className="flex justify-end gap-3">

        <button
          type="button"
          onClick={onCancel}
          className="rounded-xl border px-6 py-3"
        >
          Cancel
        </button>

        <button
          className="rounded-xl bg-blue-600 px-6 py-3 text-white hover:bg-blue-700 transition"
        >
          {editingGoal
            ? "Update Goal"
            : "Create Goal"}
        </button>

      </div>

    </form>
  );
}