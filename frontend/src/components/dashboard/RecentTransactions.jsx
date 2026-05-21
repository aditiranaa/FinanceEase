const RecentTransactions = () => {
  return (
    <div
      style={{
        marginTop: "30px",
      }}
    >
      <h2>Recent Transactions</h2>

      <table border="1" cellPadding="10">
        <thead>
          <tr>
            <th>Description</th>
            <th>Amount</th>
          </tr>
        </thead>

        <tbody>
          <tr>
            <td>Netflix</td>
            <td>$15</td>
          </tr>

          <tr>
            <td>Salary</td>
            <td>$3000</td>
          </tr>
        </tbody>
      </table>
    </div>
  );
};

export default RecentTransactions;