import {
  useEffect,
  useState,
} from "react";

import {
  getBudgets,
  createBudget,
} from "../../api/authApi";

const BudgetManager = () => {

  const [formData, setFormData] =
    useState({
      category: "",
    });

  const [budgets, setBudgets] =
    useState([]);

  const handleChange = (e) => {

    setFormData({
      ...formData,
      [e.target.name]:
        e.target.value,
    });

  };

  const fetchBudgets = async () => {

    try {

      const data =
        await getBudgets();

      setBudgets(data);

    } catch (error) {

      console.log(error);

    }

  };

  useEffect(() => {

    fetchBudgets();

  }, []);

  const handleSubmit =
    async (e) => {

      e.preventDefault();

      try {

        await createBudget(
          formData
        );

        await fetchBudgets();

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

      <div className="mt-6 space-y-3">

        {budgets.length === 0 ? (

          <p className="text-gray-400">
            No budgets yet
          </p>

        ) : (

          budgets.map((budget) => (

            <div
              key={budget.id}
              className="
                bg-gray-50
                p-4
                rounded-xl
              "
            >

              <h3
                className="
                  font-semibold
                  text-gray-800
                "
              >
                {budget.category}
              </h3>

            </div>

          ))

        )}

      </div>

    </div>

  );
};

export default BudgetManager;