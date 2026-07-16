import React, { useEffect, useState } from "react";
import {
  Bell,
  User,
  Settings,
  ChevronDown,
  LogOut,
} from "lucide-react";
import { useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";
import { useTheme } from "../../context/ThemeContext";
import { getProfile } from "../../api/authApi";

const Navbar = () => {
  const navigate = useNavigate();
  const location = useLocation();

  const { logout } = useAuth();
  const { darkMode, setDarkMode } = useTheme();

  const [profile, setProfile] = useState(null);
  const [isProfileOpen, setIsProfileOpen] = useState(false);

  useEffect(() => {
    const fetchProfile = async () => {
      try {
        const data = await getProfile();
        setProfile(data);
      } catch (error) {
        console.error("Error fetching profile:", error);
      }
    };

    fetchProfile();
  }, []);

  const handleLogout = () => {
    logout();
    navigate("/");
  };

  const pageInfo = {
    "/dashboard": "Overview",
    "/transactions": "Transactions",
    "/budgets": "Budgets",
    "/goals": "Goals",
    "/analytics": "Analytics",
    "/profile": "Profile",
  };

  const title =
    pageInfo[location.pathname] || "FinanceEase";

  const getInitials = (name) => {
    if (!name) return "JD";

    return name
      .split(" ")
      .map((n) => n[0])
      .join("")
      .toUpperCase()
      .slice(0, 2);
  };

  return (
    <header className="mb-6 flex items-center justify-between border-b border-slate-200/80 pb-4 dark:border-white/[0.05]">

      {/* Left */}
      <h1 className="text-xl font-bold text-slate-800 dark:text-white">
        {title}
      </h1>

      {/* Right */}
      <div className="flex items-center gap-4">

        {/* Notifications */}
        <button className="relative rounded-full p-1.5 transition hover:bg-slate-100 dark:hover:bg-slate-800">
          <Bell className="h-4 w-4 text-slate-600 dark:text-slate-300" />

          <span className="absolute right-1 top-1 flex h-3.5 w-3.5 items-center justify-center rounded-full border border-white bg-blue-500 text-[8px] font-bold text-white dark:border-slate-900">
            3
          </span>
        </button>

        {/* Theme */}
        <button
          onClick={() => setDarkMode(!darkMode)}
          className="rounded-full p-1.5 transition hover:bg-slate-100 dark:hover:bg-slate-800"
        >
          <Settings className="h-4 w-4 text-slate-600 dark:text-slate-300" />
        </button>

        {/* Profile */}
        <div className="relative">

          <button
            onClick={() =>
              setIsProfileOpen(!isProfileOpen)
            }
            className="flex items-center gap-2 rounded-lg p-1 transition hover:bg-slate-100 dark:hover:bg-slate-800"
          >
            <div className="flex h-7 w-7 items-center justify-center rounded-full bg-blue-600 text-[10px] font-bold text-white">
              {profile
                ? getInitials(profile.name)
                : "JD"}
            </div>

            <span className="hidden text-xs font-semibold text-slate-700 dark:text-slate-200 sm:inline">
              {profile
                ? profile.name
                : "John Doe"}
            </span>

            <ChevronDown className="h-3 w-3 text-slate-400" />
          </button>

          {isProfileOpen && (
            <>
              <div
                className="fixed inset-0 z-30"
                onClick={() =>
                  setIsProfileOpen(false)
                }
              />

              <div className="absolute right-0 z-40 mt-2 w-48 rounded-xl border border-slate-100 bg-white p-1.5 shadow-lg dark:border-white/[0.08] dark:bg-slate-900">

                <div className="border-b border-slate-100 px-3 py-2 dark:border-white/[0.04]">
                  <p className="text-xs font-bold text-slate-700 dark:text-slate-200">
                    {profile
                      ? profile.name
                      : "John Doe"}
                  </p>

                  <p className="truncate text-[10px] text-slate-400">
                    {profile
                      ? profile.email
                      : "john@example.com"}
                  </p>
                </div>

                <button
                  onClick={() => {
                    navigate("/profile");
                    setIsProfileOpen(false);
                  }}
                  className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left text-xs font-medium text-slate-600 transition hover:bg-slate-50 dark:text-slate-300 dark:hover:bg-slate-800"
                >
                  <User className="h-3.5 w-3.5" />
                  My Profile
                </button>

                <button
                  onClick={handleLogout}
                  className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left text-xs font-medium text-rose-600 transition hover:bg-rose-50 dark:hover:bg-rose-950/20"
                >
                  <LogOut className="h-3.5 w-3.5" />
                  Sign Out
                </button>

              </div>
            </>
          )}

        </div>

      </div>

    </header>
  );
};

export default Navbar;