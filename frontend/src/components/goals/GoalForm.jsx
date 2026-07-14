import { useEffect, useMemo, useState } from "react";

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
  const [form, setForm] = useState(initialState);
  const [errors, setErrors] = useState({});

  useEffect(() => {
    if (editingGoal) {
      setForm({
        ...initialState,
        ...editingGoal,
        deadline: editingGoal.deadline
          ? editingGoal.deadline.slice(0, 10)
          : "",
      });
    } else {
      setForm(initialState);
    }

    setErrors({});
  }, [editingGoal]);

  const handleChange = ({ target }) => {
    const { name, value } = target;

    setForm((prev) => ({
      ...prev,
      [name]: value,
    }));

    setErrors((prev) => ({
      ...prev,
      [name]: "",
    }));
  };

  const progress = useMemo(() => {
    const target = Number(form.target_amount || 0);
    const current = Number(form.current_amount || 0);

    if (!target) return 0;

    return Math.min((current / target) * 100, 100);
  }, [form.current_amount, form.target_amount]);

  const validate = () => {
    const nextErrors = {};

    if (!form.title.trim()) {
      nextErrors.title = "Title is required.";
    }

    if (!form.target_amount || Number(form.target_amount) <= 0) {
      nextErrors.target_amount =
        "Enter a valid target amount.";
    }

    if (Number(form.current_amount || 0) < 0) {
      nextErrors.current_amount =
        "Saved amount cannot be negative.";
    }

    if (
      Number(form.current_amount || 0) >
      Number(form.target_amount || 0)
    ) {
      nextErrors.current_amount =
        "Saved amount cannot exceed target.";
    }

    setErrors(nextErrors);

    return Object.keys(nextErrors).length === 0;
  };

  const handleSubmit = (e) => {
    e.preventDefault();

    if (!validate()) return;

    onSubmit({
      ...form,
      target_amount: Number(form.target_amount),
      current_amount: Number(form.current_amount || 0),
    });

    setForm(initialState);
    setErrors({});
  };

  return (
    <form
      onSubmit={handleSubmit}
      className="space-y-4"
    >
      <div>
        <label className="mb-2 block text-xs font-semibold">
          Goal Title
        </label>

        <input
          name="title"
          value={form.title}
          onChange={handleChange}
          placeholder="Enter a goal"
          required
          className="
            w-full
            rounded-xl
            border
            border-gray-300
            dark:border-gray-700
            bg-white
            dark:bg-gray-900
            px-4
            py-3
            outline-none
            focus:ring-2
            focus:ring-blue-500
          "
        />

        {errors.title && (
          <p className="mt-2 text-xs text-red-600">
            {errors.title}
          </p>
        )}
      </div>

      <div className="grid gap-5 md:grid-cols-2">
        <div>
          <label className="mb-2 block text-xs font-semibold">
            Category
          </label>

          <select
            name="category"
            value={form.category}
            onChange={handleChange}
            className="
              w-full
              rounded-xl
              border
              border-gray-300
              dark:border-gray-700
              bg-white
              dark:bg-gray-900
              px-4
              py-3
            "
          >
            {CATEGORIES.map((category) => (
              <option
                key={category}
                value={category}
              >
                {category}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="mb-2 block text-xs font-semibold">
            Deadline
          </label>

          <input
            type="date"
            name="deadline"
            value={form.deadline}
            onChange={handleChange}
            className="
              w-full
              rounded-xl
              border
              border-gray-300
              dark:border-gray-700
              bg-white
              dark:bg-gray-900
              px-4
              py-3
            "
          />
        </div>
      </div>

      <div className="grid gap-5 md:grid-cols-2">
        <div>
          <label className="mb-2 block text-xs font-semibold">
            Target Amount
          </label>

          <input
            type="number"
            min="1"
            step="0.01"
            name="target_amount"
            value={form.target_amount}
            onChange={handleChange}
            required
            className="
              w-full
              rounded-xl
              border
              border-gray-300
              dark:border-gray-700
              bg-white
              dark:bg-gray-900
              px-4
              py-3
            "
          />

          {errors.target_amount && (
            <p className="mt-2 text-xs text-red-600">
              {errors.target_amount}
            </p>
          )}
        </div>

        <div>
          <label className="mb-2 block text-xs font-semibold">
            Current Saved
          </label>

          <input
            type="number"
            min="0"
            step="0.01"
            name="current_amount"
            value={form.current_amount}
            onChange={handleChange}
            className="
              w-full
              rounded-xl
              border
              border-gray-300
              dark:border-gray-700
              bg-white
              dark:bg-gray-900
              px-4
              py-3
            "
          />

          {errors.current_amount && (
            <p className="mt-2 text-xs text-red-600">
              {errors.current_amount}
            </p>
          )}
        </div>
      </div>

      <div>
        <div className="mb-2 flex items-center justify-between text-xs">
          <span className="font-medium text-gray-600 dark:text-gray-300">
            Progress Preview
          </span>

          <span className="font-semibold">
            {progress.toFixed(0)}%
          </span>
        </div>

        <div className="h-2 overflow-hidden rounded-full bg-gray-200 dark:bg-gray-700">
          <div
            className="h-full rounded-full bg-blue-600 transition-all"
            style={{ width: `${progress}%` }}
          />
        </div>
      </div>

      <div className="flex justify-end gap-3">
        <button
          type="button"
          onClick={onCancel}
          className="
            rounded-xl
            border
            border-gray-300
            dark:border-gray-700
            px-6
            py-3
          "
        >
          Cancel
        </button>

        <button
          type="submit"
          className="
            rounded-xl
            bg-blue-600
            px-6
            py-3
            text-white
            transition
            hover:bg-blue-700
          "
        >
          {editingGoal ? "Update Goal" : "Create Goal"}
        </button>
      </div>
    </form>
  );
}