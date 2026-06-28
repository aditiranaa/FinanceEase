import { useState } from "react";

import {
  Trash2,
  Pencil,
  Save,
  X,
} from "lucide-react";

import {
  deleteTransaction,
  updateTransaction,
} from "../../api/authApi";

const RecentTransactions = ({
  transactions,
  fetchTransactions,
}) => {
  const [filter, setFilter] =
  useState("all");

  const [typeFilter,
  setTypeFilter] =
  useState("all");

  const [searchTerm, setSearchTerm] =
    useState("");

  const [editingId, setEditingId] =
    useState(null);

  const [editData, setEditData] =
    useState({
      description: "",
      category: "",
      amount: "",
      date: "",
    });

  const filteredTransactions =
  transactions.filter(
    (transaction) => {

      const matchesSearch =
        transaction.description
          .toLowerCase()
          .includes(
            searchTerm.toLowerCase()
          ) ||
        transaction.category
          .toLowerCase()
          .includes(
            searchTerm.toLowerCase()
          );

      if (!matchesSearch)
        return false;

      if (
        typeFilter === "income" &&
        transaction.amount <= 0
      ) {

        return false;

      }

      if (
        typeFilter === "expense" &&
        transaction.amount > 0
      ) {

       return false;

  }

      const transactionDate =
        new Date(
          transaction.date
        );

      const today =
        new Date();

      if (filter === "today") {

        return (
          transactionDate
            .toDateString() ===
          today.toDateString()
        );

      }

      if (filter === "month") {

        return (
          transactionDate
            .getMonth() ===
            today.getMonth() &&
          transactionDate
            .getFullYear() ===
            today.getFullYear()
        );

      }

      return true;

    }
  );

  const handleDelete = async (id) => {

    const confirmDelete =
      window.confirm(
        "Delete this transaction?"
      );

    if (!confirmDelete) return;

    try {

      await deleteTransaction(id);

      await fetchTransactions();

    } catch (error) {

      console.log(error);

    }

  };

  const handleUpdate =
    async (id) => {

      try {

        await updateTransaction(
          id,
          editData
        );

        setEditingId(null);

        await fetchTransactions();

      } catch (error) {

        console.log(error);

      }

    };

  return (

    <div
      className="
        mt-8
        bg-white
        rounded-2xl
        shadow-sm
        p-6
      "
    >

      <div
        className="
          flex
          justify-between
          items-center
          mb-6
        "
      >

        <div>

          <h2
            className="
              text-2xl
              font-bold
              text-gray-800
            "
          >
            Recent Transactions
          </h2>

          <p className="text-gray-500">
            Latest financial activity
          </p>

        </div>

      </div>

      <input
        type="text"
        placeholder="Search transactions..."
        value={searchTerm}
        onChange={(e) =>
          setSearchTerm(
            e.target.value
          )
        }
        className="
          border
          rounded-lg
          px-4
          py-2
          mb-6
          w-full
        "
      />
      <select
  value={filter}
  onChange={(e) =>
    setFilter(
      e.target.value
    )
  }
  className="
    border
    rounded-lg
    px-4
    py-2
    mb-6
  "
>

  <option value="all">
    All
  </option>

  <option value="today">
    Today
  </option>

  <option value="month">
    This Month
  </option>

</select>

<select
  value={typeFilter}
  onChange={(e) =>
    setTypeFilter(
      e.target.value
    )
  }
  className="
    border
    rounded-lg
    px-4
    py-2
    mb-6
    ml-3
  "
>

  <option value="all">
    All Types
  </option>

  <option value="income">
    Income
  </option>

  <option value="expense">
    Expense
  </option>

</select>

      <div className="overflow-x-auto">

        <table className="w-full">

          <thead>

            <tr
              className="
                text-left
                border-b
                text-gray-500
              "
            >

              <th className="pb-4">
                Description
              </th>

              <th className="pb-4">
                Category
              </th>

              <th className="pb-4">
                Amount
              </th>

              <th className="pb-4">
                Action
              </th>

            </tr>

          </thead>

          <tbody>

            {filteredTransactions.length === 0 ? (

              <tr>

                <td
                  colSpan="4"
                  className="
                    text-center
                    py-10
                    text-gray-400
                  "
                >
                  No transactions found
                </td>

              </tr>

            ) : (

              filteredTransactions.map(
                (transaction) => (

                  <tr
                    key={transaction.id}
                    className="
                      border-b
                      hover:bg-gray-50
                      transition
                    "
                  >

                    <td className="py-5">

                      {editingId ===
                      transaction.id ? (

                        <input
                          type="text"
                          value={
                            editData.description
                          }
                          onChange={(e) =>
                            setEditData({
                              ...editData,
                              description:
                                e.target.value,
                            })
                          }
                          className="
                            border
                            rounded
                            px-2
                            py-1
                          "
                        />

                      ) : (

                        <p
                          className="
                            font-semibold
                            text-gray-800
                          "
                        >
                          {
                            transaction.description
                          }
                        </p>

                      )}

                    </td>

                    <td className="py-5">

                      {editingId ===
                      transaction.id ? (

                        <input
                          type="text"
                          value={
                            editData.category
                          }
                          onChange={(e) =>
                            setEditData({
                              ...editData,
                              category:
                                e.target.value,
                            })
                          }
                          className="
                            border
                            rounded
                            px-2
                            py-1
                          "
                        />

                      ) : (

                        <span
                          className="
                            bg-gray-100
                            text-gray-700
                            px-3
                            py-1
                            rounded-full
                            text-sm
                          "
                        >
                          {
                            transaction.category
                          }
                        </span>

                      )}

                    </td>

                    <td className="py-5">

                      {editingId ===
                      transaction.id ? (

                        <input
                          type="number"
                          value={
                            editData.amount
                          }
                          onChange={(e) =>
                            setEditData({
                              ...editData,
                              amount:
                                e.target.value,
                            })
                          }
                          className="
                            border
                            rounded
                            px-2
                            py-1
                          "
                        />

                      ) : (

                        <span
                          className={`
                            font-bold
                            ${
                              transaction.amount > 0
                                ? "text-green-600"
                                : "text-red-500"
                            }
                          `}
                        >
                          ₹
                          {Number(
                            transaction.amount
                          ).toLocaleString(
                            "en-IN"
                          )}
                        </span>

                      )}

                    </td>

                    <td
                      className="
                        py-5
                        flex
                        gap-3
                      "
                    >

                      {editingId ===
                      transaction.id ? (

                        <>

                          <button
                            onClick={() =>
                              handleUpdate(
                                transaction.id
                              )
                            }
                            className="
                              text-green-600
                            "
                          >
                            <Save size={18} />
                          </button>

                          <button
                            onClick={() =>
                              setEditingId(
                                null
                              )
                            }
                            className="
                              text-gray-500
                            "
                          >
                            <X size={18} />
                          </button>

                        </>

                      ) : (

                        <>

                          <button
                            onClick={() => {

                              setEditingId(
                                transaction.id
                              );

                              setEditData({
                                description:
                                  transaction.description,
                                category:
                                  transaction.category,
                                amount:
                                  transaction.amount,
                                date:
                                  transaction.date,
                              });

                            }}
                            className="
                              text-blue-500
                              hover:text-blue-700
                            "
                          >
                            <Pencil size={18} />
                          </button>

                          <button
                            onClick={() =>
                              handleDelete(
                                transaction.id
                              )
                            }
                            className="
                              text-red-500
                              hover:text-red-700
                            "
                          >
                            <Trash2 size={18} />
                          </button>

                        </>

                      )}

                    </td>

                  </tr>

                )
              )

            )}

          </tbody>

        </table>

      </div>

    </div>

  );

};

export default RecentTransactions;
