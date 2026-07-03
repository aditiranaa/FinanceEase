import {
  Bell,
  Search,
  User,
  Moon,
  Sun,
  LayoutDashboard,
  Receipt,
  Wallet,
  Target,
  BarChart3,
} from "lucide-react";

import {
  useNavigate,
  useLocation,
} from "react-router-dom";

import { useAuth }
from "../../context/AuthContext";

import { useTheme }
from "../../context/ThemeContext";

const Navbar = () => {

  const navigate =
    useNavigate();

  const location =
    useLocation();

  const { logout } =
    useAuth();

  const {
    darkMode,
    setDarkMode,
  } = useTheme();

  const handleLogout = () => {

    logout();

    navigate("/");

  };

  const pageInfo = {

    "/dashboard": {
      title: "Dashboard",
      icon: LayoutDashboard,
    },

    "/transactions": {
      title: "Transactions",
      icon: Receipt,
    },

    "/budgets": {
      title: "Budgets",
      icon: Wallet,
    },

    "/goals": {
      title: "Goals",
      icon: Target,
    },

    "/analytics": {
      title: "Analytics",
      icon: BarChart3,
    },

    "/profile": {
      title: "Profile",
      icon: User,
    },

  };

  const currentPage =
    pageInfo[
      location.pathname
    ] || {
      title: "FinanceEase",
      icon: LayoutDashboard,
    };

  const PageIcon =
    currentPage.icon;

  return (

    <div
      className="
      bg-white
      dark:bg-gray-900
      rounded-3xl
      p-6
      shadow-lg
      border
      border-gray-100
      dark:border-gray-700
      hover:-translate-y-2
      hover:shadow-2xl
      transition-all
      duration-300
"
    >

      <div
        className="
          flex
          items-center
          gap-4
        "
      >

        <div
          className="
            bg-green-500
            text-white
            p-3
            rounded-xl
          "
        >

          <PageIcon
            size={24}
          />

        </div>

        <div>

          <h1
            className="
              text-3xl
              font-bold
              text-gray-800
              dark:text-white
            "
          >
            {
              currentPage.title
            }
          </h1>

          <p
            className="
              text-gray-500
              dark:text-gray-400
            "
          >
            Welcome back 👋
          </p>

        </div>

      </div>

      <div
        className="
          flex
          items-center
          gap-5
        "
      >

        <Search
          className="
            text-gray-500
            dark:text-gray-300
            cursor-pointer
          "
        />

        <Bell
          className="
            text-gray-500
            dark:text-gray-300
            cursor-pointer
          "
        />

        <button
          onClick={() =>
            setDarkMode(
              !darkMode
            )
          }
          className="
            bg-gray-200
            dark:bg-gray-700
            p-2
            rounded-full
            transition
          "
        >

          {

            darkMode

            ?

            <Sun
              size={20}
              className="text-yellow-400"
            />

            :

            <Moon
              size={20}
              className="text-gray-700"
            />

          }

        </button>

        <div
          className="
            bg-gray-100
            dark:bg-gray-700
            p-2
            rounded-full
          "
        >

          <User
            size={22}
            className="
              dark:text-white
            "
          />

        </div>

        <button
          onClick={handleLogout}
          className="
            bg-red-500
            hover:bg-red-600
            transition
            text-white
            px-4
            py-2
            rounded-lg
          "
        >
          Logout
        </button>

      </div>

    </div>

  );

};

export default Navbar;