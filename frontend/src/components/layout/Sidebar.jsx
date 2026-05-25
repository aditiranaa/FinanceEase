import {
  LayoutDashboard,
  Receipt,
  Wallet,
  Target,
} from "lucide-react";

const Sidebar = () => {
  return (

    <div
      className="
        w-64
        min-h-screen
        bg-gray-900
        text-white
        p-6
      "
    >

      <h2
        className="
          text-3xl
          font-bold
          mb-10
          text-green-400
        "
      >
        FinanceEase
      </h2>

      <div className="space-y-6">

        <div
          className="
            flex
            items-center
            gap-3
            hover:text-green-400
            cursor-pointer
            transition
          "
        >
          <LayoutDashboard size={22} />

          <p className="text-lg">
            Dashboard
          </p>
        </div>

        <div
          className="
            flex
            items-center
            gap-3
            hover:text-green-400
            cursor-pointer
            transition
          "
        >
          <Receipt size={22} />

          <p className="text-lg">
            Transactions
          </p>
        </div>

        <div
          className="
            flex
            items-center
            gap-3
            hover:text-green-400
            cursor-pointer
            transition
          "
        >
          <Wallet size={22} />

          <p className="text-lg">
            Budgets
          </p>
        </div>

        <div
          className="
            flex
            items-center
            gap-3
            hover:text-green-400
            cursor-pointer
            transition
          "
        >
          <Target size={22} />

          <p className="text-lg">
            Goals
          </p>
        </div>

      </div>

    </div>
  );
};

export default Sidebar;