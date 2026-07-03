import { useState } from "react";

import {
  useNavigate,
  useLocation,
} from "react-router-dom";

import {
  LayoutDashboard,
  Receipt,
  Wallet,
  Target,
  User,
  BarChart3,
  Menu,
  X,
} from "lucide-react";


const Sidebar = () => {

  const [isOpen, setIsOpen] =
    useState(false);

  const navigate = useNavigate();
  const location = useLocation();

  const menuItems = [
  {
    name: "Dashboard",
    path: "/dashboard",
    icon: LayoutDashboard,
  },
  {
    name: "Transactions",
    path: "/transactions",
    icon: Receipt,
  },
  {
    name: "Budgets",
    path: "/budgets",
    icon: Wallet,
  },
  {
    name: "Goals",
    path: "/goals",
    icon: Target,
  },
  {
    name: "Analytics",
    path: "/analytics",
    icon: BarChart3,
  },
  {
    name: "Profile",
    path: "/profile",
    icon: User,
  },
];


  return (

    <>

      <button
        className="
          md:hidden
          fixed
          top-4
          left-4
          z-50
          bg-gray-900
          dark:bg-gray-800
          text-white
          p-2
          rounded-lg
          transition-colors
          "
        onClick={() =>
          setIsOpen(!isOpen)
        }
      >

        {
          isOpen
            ? <X />
            : <Menu />
        }

      </button>

      <div
        className={`
          fixed
          top-0
          left-0
          h-screen
          bg-gray-900
          dark:bg-black
          text-white
          p-6
          w-64
          transform
          transition-transform
          transition-colors
          duration-300
          z-40

          ${
          isOpen
          ? "translate-x-0"
          : "-translate-x-full"
          }

          md:translate-x-0
          md:static
`}
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

       <div className="space-y-3">

  {menuItems.map((item) => {

    const Icon = item.icon;

    return (

      <div
        key={item.path}
        onClick={() => {

          navigate(item.path);

          setIsOpen(false);

        }}
        className={`
          flex
          items-center
          gap-3
          px-4
          py-3
          rounded-xl
          cursor-pointer
          transition-all
          duration-200

          ${
            location.pathname === item.path
              ? "bg-green-500 text-white shadow-lg"
              : "hover:bg-gray-800 hover:text-green-400"
          }
        `}
      >

        <Icon size={22} />

        <p className="text-lg">
          {item.name}
        </p>

      </div>

    );

  })}

</div>

</div>

    </>

  );

};

export default Sidebar;

