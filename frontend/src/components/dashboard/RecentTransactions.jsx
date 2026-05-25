const RecentTransactions = ({
  transactions,
}) => {

  return (

    <div className="mt-8 bg-white p-6 rounded-lg shadow">

      <h2 className="text-2xl font-semibold mb-4">
        Recent Transactions
      </h2>

      <table className="w-full">

        <thead>

          <tr className="border-b">

            <th className="text-left py-3">
              Description
            </th>

            <th className="text-left py-3">
              Category
            </th>

            <th className="text-left py-3">
              Amount
            </th>

          </tr>

        </thead>

        <tbody>

          {transactions.map(
            (transaction) => (

            <tr
              key={transaction.id}
              className="border-b"
            >

              <td className="py-3">
                {transaction.description}
              </td>

              <td className="py-3">
                {transaction.category}
              </td>

              <td
                className={`
                  py-3
                  font-semibold
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
          ))}

        </tbody>

      </table>

    </div>
  );
};

export default RecentTransactions;