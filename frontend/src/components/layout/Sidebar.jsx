const Sidebar = () => {
  return (
    <div className="w-64 h-screen bg-gray-900 text-white p-5">

      <h2 className="text-2xl font-bold mb-5">
        FinanceEase
      </h2>

      <div className="space-y-3">
        <p>Dashboard</p>
        <p>Transactions</p>
        <p>Budgets</p>
        <p>Goals</p>
      </div>

    </div>
  );
};

export default Sidebar;