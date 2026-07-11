import {
  Bell,
  Search,
  User,
  Moon,
  Sun,
} from "lucide-react";

import { useNavigate, useLocation } from "react-router-dom";

import { useAuth } from "../../context/AuthContext";
import { useTheme } from "../../context/ThemeContext";

const Navbar = () => {
  const navigate = useNavigate();
  const location = useLocation();

  const { logout } = useAuth();
  const { darkMode, setDarkMode } = useTheme();

  const handleLogout = () => {
    logout();
    navigate("/");
  };

  return (
  <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-2xl px-8 py-4 shadow-sm">

    <div className="flex items-center justify-between">

      <div className="relative w-80">

        <Search
          size={18}
          className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-400"
        />

        <input
          type="text"
          placeholder="Search..."
          className="
            w-full
            pl-11
            pr-4
            py-2.5
            rounded-xl
            border
            border-gray-200
            dark:border-gray-700
            bg-gray-50
            dark:bg-gray-800
            focus:outline-none
            focus:ring-2
            focus:ring-green-500
          "
        />

      </div>

      <div className="flex items-center gap-5">

        <button className="relative">

          <Bell
            size={21}
            className="text-gray-600 dark:text-gray-300"
          />

          <span className="absolute -top-1 -right-1 h-2.5 w-2.5 rounded-full bg-red-500" />

        </button>

        <button
          onClick={() => setDarkMode(!darkMode)}
          className="p-2 rounded-full bg-gray-100 dark:bg-gray-700"
        >
          {darkMode ? (
            <Sun
              size={18}
              className="text-yellow-400"
            />
          ) : (
            <Moon
              size={18}
              className="text-gray-700"
            />
          )}
        </button>

        <div className="w-10 h-10 rounded-full bg-green-500 flex items-center justify-center text-white font-semibold">
          U
        </div>

        <button
          onClick={handleLogout}
          className="rounded-xl bg-red-500 px-4 py-2 text-white hover:bg-red-600 transition"
        >
          Logout
        </button>

      </div>

    </div>

  </div>
);
};

export default Navbar;