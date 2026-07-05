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

export default function GoalForm({ onSubmit, editingGoal, onCancel }) {
  const [form, setForm] = useState(initialState);

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

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const submit = (e) => {
    e.preventDefault();
    onSubmit(form);
    setForm(initialState);
  };

  return (
    <form
      onSubmit={submit}
      className="bg-white dark:bg-gray-900 rounded-xl shadow-md p-6 space-y-4"
    >
      <h2 className="text-xl font-bold">
        {editingGoal ? "Edit Goal" : "Add Goal"}
      </h2>

      <input
        className="w-full border rounded-lg p-3"
        placeholder="Goal Title"
        name="title"
        value={form.title}
        onChange={handleChange}
        required
      />

      <select
        className="w-full border rounded-lg p-3"
        name="category"
        value={form.category}
        onChange={handleChange}
      >
        {CATEGORIES.map((cat) => (
          <option key={cat} value={cat}>
            {cat}
          </option>
        ))}
      </select>

      <div className="grid gap-4 md:grid-cols-2">
        <input
          className="w-full border rounded-lg p-3"
          type="number"
          placeholder="Target Amount"
          name="target_amount"
          value={form.target_amount}
          onChange={handleChange}
          required
          min="0"
        />

        <input
          className="w-full border rounded-lg p-3"
          type="number"
          placeholder="Current Amount"
          name="current_amount"
          value={form.current_amount}
          onChange={handleChange}
          min="0"
        />
      </div>

      <input
        className="w-full border rounded-lg p-3"
        type="date"
        name="deadline"
        value={form.deadline}
        onChange={handleChange}
      />

      <div className="flex gap-3">
        <button className="px-5 py-2 rounded-lg bg-green-600 text-white">
          {editingGoal ? "Update" : "Save"}
        </button>

        {editingGoal && (
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
