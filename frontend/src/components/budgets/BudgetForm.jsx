import { useState, useEffect } from "react";
import { X } from "lucide-react";

export default function BudgetForm({
  editingBudget,
  onSubmit,
  onCancel,
}) {
  const isEditing = Boolean(editingBudget);

  const [category, setCategory] = useState("");
  const [description, setDescription] = useState("");
  const [limit, setLimit] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState("");

  useEffect(() => {
    if (editingBudget) {
      setCategory(editingBudget.category || "");
      setDescription(editingBudget.description || "");
      setLimit(
        editingBudget.limit != null
          ? String(editingBudget.limit)
          : ""
      );
    } else {
      setCategory("");
      setDescription("");
      setLimit("");
    }

    setFormError("");
  }, [editingBudget]);

  async function handleSubmit(e) {
    e.preventDefault();

    setFormError("");

    const numericLimit = parseFloat(limit);

    if (!category.trim()) {
      setFormError("Category is required.");
      return;
    }

    if (
      !limit ||
      Number.isNaN(numericLimit) ||
      numericLimit <= 0
    ) {
      setFormError(
        "Enter a monthly limit greater than 0."
      );
      return;
    }

    try {
      setSubmitting(true);

      await onSubmit({
        category: category.trim(),
        description: description.trim(),
        limit: numericLimit,
      });

      if (!isEditing) {
        setCategory("");
        setDescription("");
        setLimit("");
      }
    } catch (err) {
      setFormError(
        err?.message ||
          "Something went wrong. Please try again."
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className="rounded-3xl border border-gray-100 bg-white p-8 shadow-sm">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">
            {isEditing
              ? "Edit Budget"
              : "Create Budget"}
          </h2>

          <p className="mt-2 text-gray-500">
            {isEditing
              ? "Update your monthly budget."
              : "Set a monthly spending target for a category."}
          </p>
        </div>

        {isEditing && (
          <button
            type="button"
            onClick={onCancel}
            className="rounded-xl p-2 text-gray-400 transition hover:bg-gray-100 hover:text-gray-700"
            aria-label="Cancel editing"
          >
            <X size={22} />
          </button>
        )}
      </div>

      <form
        onSubmit={handleSubmit}
        className="space-y-6"
      >
        <div className="grid gap-6 lg:grid-cols-3">
          <div>
            <label className="mb-2 block text-sm font-semibold text-gray-700">
              Category
            </label>

            <input
              value={category}
              onChange={(e) =>
                setCategory(e.target.value)
              }
              placeholder="Groceries"
              className="h-14 w-full rounded-xl border border-gray-200 px-4 text-gray-900 outline-none transition focus:border-emerald-500 focus:ring-4 focus:ring-emerald-100"
            />
          </div>

          <div>
            <label className="mb-2 block text-sm font-semibold text-gray-700">
              Description
            </label>

            <input
              value={description}
              onChange={(e) =>
                setDescription(e.target.value)
              }
              placeholder="Food and household essentials"
              className="h-14 w-full rounded-xl border border-gray-200 px-4 text-gray-900 outline-none transition focus:border-emerald-500 focus:ring-4 focus:ring-emerald-100"
            />
          </div>

          <div>
            <label className="mb-2 block text-sm font-semibold text-gray-700">
              Monthly Limit
            </label>

            <input
              type="number"
              min="0"
              step="0.01"
              value={limit}
              onChange={(e) =>
                setLimit(e.target.value)
              }
              placeholder="1000"
              className="h-14 w-full rounded-xl border border-gray-200 px-4 text-gray-900 outline-none transition focus:border-emerald-500 focus:ring-4 focus:ring-emerald-100"
            />
          </div>
        </div>

        {formError && (
          <div className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-600">
            {formError}
          </div>
        )}

        <div className="flex items-center gap-4 pt-2">
          <button
            type="submit"
            disabled={submitting}
            className="rounded-xl bg-emerald-600 px-8 py-3 font-semibold text-white transition hover:bg-emerald-700 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {submitting
              ? "Saving..."
              : isEditing
              ? "Save Changes"
              : "Create Budget"}
          </button>

          {isEditing && (
            <button
              type="button"
              onClick={onCancel}
              className="rounded-xl border border-gray-200 px-6 py-3 font-medium text-gray-700 transition hover:bg-gray-50"
            >
              Cancel
            </button>
          )}
        </div>
      </form>
    </section>
  );
}