const Sidebar = () => {
  return (
    <div className="w-64 h-screen bg-gray-900 text-white p-5">

      <h2 className="text-3xl font-bold mb-8">
        FinanceEase
      </h2>

      <div className="space-y-4 text-lg">

        <p className="hover:text-green-400 cursor-pointer">
          Dashboard
        </p>

        <p className="hover:text-green-400 cursor-pointer">
          Transactions
        </p>

        <p className="hover:text-green-400 cursor-pointer">
          Budgets
        </p>

        <p className="hover:text-green-400 cursor-pointer">
          Goals
        </p>

      </div>

    </div>
  );
};

export default Sidebar;