const StatsCards = () => {
  return (

    <div
      className="
        grid
        grid-cols-1
        md:grid-cols-2
        lg:grid-cols-4
        gap-6
        mt-6
      "
    >

      <div className="bg-white p-5 rounded-lg shadow">

        <h3 className="text-gray-500">
          Total Balance
        </h3>

        <p className="text-3xl font-bold mt-2">
          $12,000
        </p>

      </div>

      <div className="bg-white p-5 rounded-lg shadow">

        <h3 className="text-gray-500">
          Income
        </h3>

        <p className="text-3xl font-bold mt-2 text-green-600">
          $8,000
        </p>

      </div>

      <div className="bg-white p-5 rounded-lg shadow">

        <h3 className="text-gray-500">
          Expenses
        </h3>

        <p className="text-3xl font-bold mt-2 text-red-500">
          $3,000
        </p>

      </div>

      <div className="bg-white p-5 rounded-lg shadow">

        <h3 className="text-gray-500">
          Savings
        </h3>

        <p className="text-3xl font-bold mt-2 text-blue-600">
          $9,000
        </p>

      </div>

    </div>
  );
};

export default StatsCards;