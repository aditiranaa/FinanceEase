import {
  useEffect,
  useState,
} from "react";

import { Trash2 } from "lucide-react";

import {
  getBudgets,
  createBudget,
  deleteBudget,
} from "../../api/authApi";


const BudgetManager = ({
  transactions,
}) => {

  const [formData, setFormData] =
    useState({
      category: "",
      amount: "",
    });
const handleDelete = async (id) => {

  const confirmDelete =
    window.confirm(
      "Delete this budget?"
    );

  if (!confirmDelete)
    return;

  try {

    await deleteBudget(id);

    await fetchBudgets();

  } catch (error) {

    console.log(error);

  }

};

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
          amount: "",
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

        <input
          type="number"
          name="amount"
          placeholder="Budget Amount"
          value={formData.amount}
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

  budgets.map((budget) => {

    const spent =
      transactions
        .filter(
          (transaction) =>
            transaction.category ===
            budget.category
        )
        .reduce(
          (total, transaction) =>
            total +
            Math.abs(
              Number(
                transaction.amount
              )
            ),
          0
        );

    const remaining =
      Number(
        budget.amount || 0
      ) - spent;

    const percentage =
      Number(
        budget.amount || 0
      ) > 0
        ? Math.min(
            (spent /
              Number(
                budget.amount
              )) *
              100,
            100
          )
        : 0;

    return (

      <div
  key={budget.id}
  className="
    bg-gray-50
    p-4
    rounded-xl
  "
>

  <div
    className="
      flex
      justify-between
      items-center
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

    <button
      onClick={() =>
        handleDelete(
          budget.id
        )
      }
      className="
        text-red-500
        hover:text-red-700
      "
    >
      <Trash2 size={18} />
    </button>

  </div>
  
        <div
          className="
            flex
            justify-between
            mt-2
            text-sm
          "
        >

          <span>
            Spent ₹
            {spent.toLocaleString(
              "en-IN"
            )}
          </span>

          <span>
            Remaining ₹
            {remaining.toLocaleString(
              "en-IN"
            )}
          </span>

        </div>

      </div>

    );

  })

)}


      </div>

    </div>

  );
};

export default BudgetManager 
;