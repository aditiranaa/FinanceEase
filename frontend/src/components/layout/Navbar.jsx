import { useState } from "react";
import {
  Bell,
  Moon,
  Sun,
  ChevronDown,
  User,
  LogOut,
} from "lucide-react";

import { useNavigate, useLocation } from "react-router-dom";

import { useAuth } from "../../context/AuthContext";
import { useTheme } from "../../context/ThemeContext";

const Navbar = () => {
  const navigate = useNavigate();
  const location = useLocation();

  const { logout } = useAuth();
  const { darkMode, setDarkMode } = useTheme();

  const [open, setOpen] = useState(false);

  const titles = {
    "/dashboard": "Dashboard",
    "/transactions": "Transactions",
    "/budgets": "Budgets",
    "/goals": "Goals",
    "/analytics": "Analytics",
    "/profile": "Profile",
  };

  const title = titles[location.pathname] || "";

  const handleLogout = () => {
    logout();
    navigate("/");
  };

  return (
    <div className="flex justify-end items-center py-2">
      <div className="flex items-center justify-between">
        

        {/* Right */}
        <div className="flex items-center gap-5">

          <button className="relative">
            <Bell
              size={20}
              className="text-gray-600 dark:text-gray-300"
            />
            <span className="absolute -top-1 -right-1 h-2.5 w-2.5 rounded-full bg-red-500" />
          </button>

          {/* Profile */}
          <div className="relative">

            <button
              onClick={() => setOpen(!open)}
              className="flex items-center gap-3"
            >
              <div className="w-7 h-7 rounded-full bg-blue-500 flex items-center justify-center text-white font-semibold">
                U
              </div>

              <span className="font-medium dark:text-white">
                John Doe
              </span>

              <ChevronDown size={12} />
            </button>

            {open && (
              <div className="absolute right-0 mt-3 w-52 rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 shadow-xl">

                <button
                  onClick={() => {
                    navigate("/profile");
                    setOpen(false);
                  }}
                  className="flex w-full items-center gap-3 px-4 py-3 hover:bg-gray-100 dark:hover:bg-gray-800"
                >
                  <User size={12} />
                  Profile
                </button>

                <button
                  onClick={handleLogout}
                  className="flex w-full items-center gap-3 px-4 py-3 text-red-500 hover:bg-red-50 dark:hover:bg-red-950"
                >
                  <LogOut size={12} />
                  Logout
                </button>

              </div>
            )}

          </div>

        </div>

      </div>
    </div>
  );
};

export default Navbar;