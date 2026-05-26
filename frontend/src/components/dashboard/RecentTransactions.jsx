const RecentTransactions = ({
  transactions,
}) => {

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

            </tr>

          </thead>

          <tbody>

            {transactions.length === 0 ? (

              <tr>

                <td
                  colSpan="3"
                  className="
                    text-center
                    py-10
                    text-gray-400
                  "
                >
                  No transactions yet
                </td>

              </tr>

            ) : (

              transactions.map(
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

                    <p
                      className="
                        font-semibold
                        text-gray-800
                      "
                    >
                      {transaction.description}
                    </p>

                  </td>

                  <td className="py-5">

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
                      {transaction.category}
                    </span>

                  </td>

                  <td
                    className={`
                      py-5
                      font-bold
                      ${
                        transaction.amount > 0
                          ? "text-green-600"
                          : "text-red-500"
                      }
                    `}
                  >

                    ${transaction.amount}

                  </td>

                </tr>
              ))
            )}

          </tbody>

        </table>

      </div>

    </div>
  );
};

export default RecentTransactions;