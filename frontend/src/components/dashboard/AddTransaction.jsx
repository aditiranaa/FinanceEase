import { useState } from "react";
import {
  Plus,
  Wallet,
  Calendar,
  Tag,
  FileText,
} from "lucide-react";
import { createTransaction } from "../../api/authApi";
import toast from "react-hot-toast";

export default function AddTransaction({
  fetchTransactions,
}) {
  const [formData, setFormData] = useState({
    description: "",
    amount: "",
    category: "",
    date: "",
  });

  const [loading, setLoading] =
    useState(false);

  const handleChange = (e) => {
    setFormData((prev) => ({
      ...prev,
      [e.target.name]:
        e.target.value,
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      setLoading(true);

      await createTransaction(formData);

      await fetchTransactions();

      toast.success(
        "Transaction added successfully."
      );

      setFormData({
        description: "",
        amount: "",
        category: "",
        date: "",
      });
    } catch (error) {
      console.error(error);

      toast.error(
        "Failed to add transaction."
      );
    } finally {
      setLoading(false);
    }
  };

  const inputClass =
    "h-12 w-full rounded-xl border border-gray-200 bg-gray-50 px-4 outline-none transition focus:border-emerald-500 focus:bg-white focus:ring-4 focus:ring-emerald-100";

  return (
    <section className="rounded-3xl border border-gray-200 bg-white p-7 shadow-sm">
      <div className="mb-8 flex items-center gap-4">
        <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-emerald-100">
          <Plus
            className="text-emerald-600"
            size={28}
          />
        </div>

        <div>
          <h2 className="text-2xl font-bold text-gray-900">
            Quick Add
          </h2>

          <p className="mt-1 text-sm text-gray-500">
            Record a new transaction.
          </p>
        </div>
      </div>

      <form
        onSubmit={handleSubmit}
        className="space-y-5"
      >
        <div>
          <label className="mb-2 flex items-center gap-2 text-sm font-semibold text-gray-700">
            <FileText size={16} />
            Description
          </label>

          <input
            name="description"
            value={formData.description}
            onChange={handleChange}
            placeholder="e.g. Grocery Shopping"
            className={inputClass}
          />
        </div>

        <div>
          <label className="mb-2 flex items-center gap-2 text-sm font-semibold text-gray-700">
            <Wallet size={16} />
            Amount
          </label>

          <input
            type="number"
            name="amount"
            value={formData.amount}
            onChange={handleChange}
            placeholder="₹0.00"
            className={inputClass}
          />
        </div>

        <div>
          <label className="mb-2 flex items-center gap-2 text-sm font-semibold text-gray-700">
            <Tag size={16} />
            Category
          </label>

          <input
            name="category"
            value={formData.category}
            onChange={handleChange}
            placeholder="Groceries"
            className={inputClass}
          />
        </div>

        <div>
          <label className="mb-2 flex items-center gap-2 text-sm font-semibold text-gray-700">
            <Calendar size={16} />
            Date
          </label>

          <input
            type="date"
            name="date"
            value={formData.date}
            onChange={handleChange}
            className={inputClass}
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          className="flex h-12 w-full items-center justify-center rounded-xl bg-emerald-600 font-semibold text-white transition hover:bg-emerald-700 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {loading
            ? "Adding..."
            : "Add Transaction"}
        </button>
      </form>
    </section>
  );
}