import {
  useState,
} from "react";

import {
  createTransaction,
} from "../../api/authApi";

import toast from "react-hot-toast";

const AddTransaction = ({
  fetchTransactions,
}) => {

  const [formData,
    setFormData] =
      useState({
        description: "",
        amount: "",
        category: "",
        date: "",
      });

  const handleChange = (e) => {

    setFormData({
      ...formData,
      [e.target.name]:
        e.target.value,
    });

  };

  const handleSubmit =
    async (e) => {

      e.preventDefault();

      try {

        await createTransaction(
          formData
        );

        await fetchTransactions();

        toast.success(
          "Transaction added successfully"
        );

        setFormData({
          description: "",
          amount: "",
          category: "",
          date: "",
        });

      }

      catch (error) {

        toast.error(
          "Failed to add transaction"
        );

        console.log(error);

      }

    };

  return (

    <div
      className="
        bg-white
        p-6
        rounded-lg
        shadow
        mt-6
      "
    >

      <h2
        className="
          text-2xl
          font-semibold
          mb-4
        "
      >
        Add Transaction
      </h2>

      <form
        onSubmit={handleSubmit}
        className="space-y-4"
      >

        <input
          type="text"
          name="description"
          placeholder="Description"
          value={
            formData.description
          }
          onChange={handleChange}
          className="
            w-full
            border
            p-3
            rounded
          "
        />

        <input
          type="number"
          name="amount"
          placeholder="Amount"
          value={formData.amount}
          onChange={handleChange}
          className="
            w-full
            border
            p-3
            rounded
          "
        />

        <input
          type="text"
          name="category"
          placeholder="Category"
          value={formData.category}
          onChange={handleChange}
          className="
            w-full
            border
            p-3
            rounded
          "
        />

        <input
          type="date"
          name="date"
          value={formData.date}
          onChange={handleChange}
          className="
            w-full
            border
            p-3
            rounded
          "
        />

        <button
          type="submit"
          className="
            bg-green-500
            text-white
            px-5
            py-3
            rounded
            hover:bg-green-600
          "
        >
          Add Transaction
        </button>

      </form>

    </div>

  );

};

export default AddTransaction;