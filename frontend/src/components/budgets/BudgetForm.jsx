import { useEffect, useState } from "react";

const initialState = {
  category: "",
  limit: "",
  spent: "",
  month: new Date().toISOString().slice(0, 7),
};

export default function BudgetForm({
  onSubmit,
  editingBudget,
  onCancel,
}) {
  const [form, setForm] =
    useState(initialState);

  useEffect(() => {
    if (editingBudget) {
      setForm(editingBudget);
    } else {
      setForm(initialState);
    }
  }, [editingBudget]);

  const handleChange = (e) => {
    setForm({
      ...form,
      [e.target.name]:
        e.target.value,
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
        {editingBudget
          ? "Edit Budget"
          : "Add Budget"}
      </h2>

      <input
        className="w-full border rounded-lg p-3"
        placeholder="Category"
        name="category"
        value={form.category}
        onChange={handleChange}
        required
      />

      <input
        className="w-full border rounded-lg p-3"
        type="number"
        placeholder="Budget Limit"
        name="limit"
        value={form.limit}
        onChange={handleChange}
        required
      />

      <input
        className="w-full border rounded-lg p-3"
        type="number"
        placeholder="Spent"
        name="spent"
        value={form.spent}
        onChange={handleChange}
      />

      <input
        className="w-full border rounded-lg p-3"
        type="month"
        name="month"
        value={form.month}
        onChange={handleChange}
      />

      <div className="flex gap-3">

        <button
          className="px-5 py-2 rounded-lg bg-blue-600 text-white"
        >
          {editingBudget
            ? "Update"
            : "Save"}
        </button>

        {editingBudget && (
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