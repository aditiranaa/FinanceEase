import { useEffect, useRef, useState } from "react";
import {
  Bell,
  Search,
  Sun,
  Moon,
  User,
  LogOut,
  ChevronDown,
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
  const [open, setOpen] = useState(false);

  const dropdownRef = useRef(null);

  useEffect(() => {
    const fetchProfile = async () => {
      try {
        const data = await getProfile();
        setProfile(data);
      } catch (err) {
        console.error(err);
      }
    };

    fetchProfile();
  }, []);

  useEffect(() => {
    const close = (e) => {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(e.target)
      ) {
        setOpen(false);
      }
    };

    document.addEventListener("mousedown", close);

    return () =>
      document.removeEventListener("mousedown", close);
  }, []);

  const handleLogout = () => {
    logout();
    navigate("/");
  };

  const pages = {
    "/dashboard": "Dashboard",
    "/transactions": "Transactions",
    "/budgets": "Budgets",
    "/goals": "Goals",
    "/analytics": "Analytics",
    "/profile": "Profile",
  };

  const title =
    pages[location.pathname] || "FinanceEase";

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
    <header className="sticky top-0 z-30 mb-8 flex items-center justify-between rounded-2xl border border-slate-200/80 bg-white/80 px-6 py-4 backdrop-blur-xl dark:border-slate-800 dark:bg-slate-900/80">
      {/* Left */}
      <div>
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white">
          {title}
        </h1>

        <p className="text-sm text-slate-500 dark:text-slate-400">
          Welcome back 👋
        </p>
      </div>

      {/* Right */}
      <div className="flex items-center gap-3">
        {/* Search */}
        <div className="relative hidden lg:block">
          <Search
            size={17}
            className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
          />

          <input
            type="text"
            placeholder="Search..."
            className="w-64 rounded-xl border border-slate-200 bg-slate-50 py-2 pl-10 pr-4 text-sm outline-none transition focus:border-emerald-500 dark:border-slate-700 dark:bg-slate-800 dark:text-white"
          />
        </div>

        {/* Notifications */}
        <button className="relative flex h-11 w-11 items-center justify-center rounded-xl bg-slate-100 transition hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700">
          <Bell
            size={18}
            className="text-slate-600 dark:text-slate-300"
          />

          <span className="absolute right-2 top-2 h-2.5 w-2.5 rounded-full bg-red-500"></span>
        </button>

        {/* Theme */}
        <button
          onClick={() => setDarkMode(!darkMode)}
          className="flex h-11 w-11 items-center justify-center rounded-xl bg-slate-100 transition hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700"
        >
          {darkMode ? (
            <Sun
              size={18}
              className="text-yellow-400"
            />
          ) : (
            <Moon
              size={18}
              className="text-slate-600"
            />
          )}
        </button>

        {/* Profile */}
        <div
          ref={dropdownRef}
          className="relative"
        >
          <button
            onClick={() => setOpen(!open)}
            className="flex items-center gap-3 rounded-xl border border-slate-200 bg-white px-2 py-2 transition hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-900"
          >
            <div className="flex h-10 w-10 items-center justify-center rounded-full bg-emerald-600 font-semibold text-white">
              {profile
                ? getInitials(profile.name)
                : "JD"}
            </div>

            <div className="hidden text-left md:block">
              <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
                {profile
                  ? profile.name
                  : "John Doe"}
              </h3>

              <p className="text-xs text-slate-500">
                {profile
                  ? profile.email
                  : "john@example.com"}
              </p>
            </div>

            <ChevronDown
              size={18}
              className={`transition ${
                open ? "rotate-180" : ""
              }`}
            />
          </button>

          {open && (
            <div className="absolute right-0 mt-3 w-56 overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-xl dark:border-slate-700 dark:bg-slate-900">
              <button
                onClick={() => {
                  navigate("/profile");
                  setOpen(false);
                }}
                className="flex w-full items-center gap-3 px-4 py-3 text-sm transition hover:bg-slate-100 dark:hover:bg-slate-800"
              >
                <User size={18} />
                My Profile
              </button>

              <div className="border-t border-slate-200 dark:border-slate-700" />

              <button
                onClick={handleLogout}
                className="flex w-full items-center gap-3 px-4 py-3 text-sm text-red-600 transition hover:bg-red-50 dark:hover:bg-red-900/20"
              >
                <LogOut size={18} />
                Sign Out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};

export default Navbar;