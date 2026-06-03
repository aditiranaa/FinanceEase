import { useState } from "react";

import {
  createBudget,
} from "../../api/authApi";

const BudgetManager = () => {

  const [formData, setFormData] =
    useState({
      category: "",
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

      await createBudget(
        formData
      );

      alert(
        "Budget Added"
      );

      setFormData({
        category: "",
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
        Budget Manager
      </h2>

      <form
        onSubmit={handleSubmit}
        className="space-y-4"
      >

        <input
          type="text"
          name="category"
          placeholder="Budget Category"
          value={formData.category}
          onChange={handleChange}
          className="
            w-full
            border
            p-3
            rounded-lg
          "
        />

        <button
          type="submit"
          className="
            bg-blue-500
            text-white
            px-5
            py-3
            rounded-lg
            hover:bg-blue-600
          "
        >
          Add Budget
        </button>

      </form>

    </div>
  );
};

export default BudgetManager;