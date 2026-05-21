const StatsCards = () => {
  return (
    <div
      style={{
        display: "flex",
        gap: "20px",
        marginTop: "20px",
      }}
    >
      <div
        style={{
          padding: "20px",
          border: "1px solid #ddd",
        }}
      >
        <h3>Total Balance</h3>
        <p>$12,000</p>
      </div>

      <div
        style={{
          padding: "20px",
          border: "1px solid #ddd",
        }}
      >
        <h3>Expenses</h3>
        <p>$3,000</p>
      </div>

      <div
        style={{
          padding: "20px",
          border: "1px solid #ddd",
        }}
      >
        <h3>Savings</h3>
        <p>$9,000</p>
      </div>
    </div>
  );
};

export default StatsCards;