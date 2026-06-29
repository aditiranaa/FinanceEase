import { useState } from "react";

import {
  useNavigate,
} from "react-router-dom";

import {
  LayoutDashboard,
  Receipt,
  Wallet,
  Target,
  Menu,
  X,
  User,
} from "lucide-react";


const Sidebar = () => {

  const [isOpen, setIsOpen] =
    useState(false);

  const navigate =
    useNavigate();

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

        <div className="space-y-6">

          <div
              onClick={() =>
                navigate("/dashboard")
              }
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

         <div
              onClick={() =>
                navigate("/profile")
              }
              className="
                flex
                items-center
                gap-3
                hover:text-green-400
                cursor-pointer
                transition
              "
            >
              <User size={22} />

              <p className="text-lg">
                Profile
              </p>

          </div>

        </div>

      </div>

    </>

  );

};

export default Sidebar;

