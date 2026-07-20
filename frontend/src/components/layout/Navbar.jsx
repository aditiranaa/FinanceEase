import { useEffect, useRef, useState } from "react";
import {
  Bell,
  Search,
  Sun,
  Moon,
  User,
  LogOut,
  ChevronDown,
  Plus,  
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

const hour = new Date().getHours();

const greeting =
  hour < 12
    ? "Good Morning"
    : hour < 18
    ? "Good Afternoon"
    : "Good Evening";

const today = new Date().toLocaleDateString("en-US", {
  weekday: "long",
  month: "long",
  day: "numeric",
});

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
    <header
  className="
    sticky
    top-5
    z-30

    mb-8

    flex
    items-center
    justify-between

    rounded-[30px]

    border
    border-white/40

    bg-white/75

    px-8
    py-5

    shadow-[0_20px_60px_rgba(15,23,42,.08)]

    backdrop-blur-2xl

    dark:border-slate-800
    dark:bg-slate-900/80
  "
>
    {/* Left */}

<div>

  <p className="text-sm font-medium text-blue-600">

    {greeting} 👋

  </p>

  <h1 className="mt-1 text-3xl font-bold tracking-tight text-slate-900 dark:text-white">

    {title}

  </h1>

  <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
  {title === "Dashboard"
    ? `Overview • ${today}`
    : `${title} • ${today}`}
</p>

</div>

      {/* Right */}
<div className="flex items-center gap-6">

  {/* Search */}
  <div className="relative hidden xl:block">
    <Search
      size={17}
      className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400"
    />

    <input
      type="text"
      placeholder="Search transactions, budgets, goals..."
      className="
        w-96
        rounded-2xl
        border
        border-slate-200
        bg-slate-100/70
        py-3
        pl-11
        pr-4
        text-sm
        outline-none

        transition-all
        duration-300

        hover:shadow-md

        focus:border-blue-500
        focus:ring-4
        focus:ring-blue-100

        dark:border-slate-700
        dark:bg-slate-800
        dark:text-white
      "
    />
  </div>


  {/* Actions */}
  <div className="flex items-center gap-3">

        {/* Notifications */}
        <button className="relative flex h-12 w-12 items-center justify-center rounded-2xl bg-slate-100 transition-all duration-300 hover:-translate-y-0.5 hover:shadow-lg hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700">
          <Bell
            size={18}
            className="text-slate-600 dark:text-slate-300"
          />

          <span
  className="
    absolute
    -right-1
    -top-1

    flex
    h-5
    w-5
    items-center
    justify-center

    rounded-full

    bg-red-500

    text-[10px]
    font-bold
    text-white
  "
>
  3
</span>
        </button>

        {/* Theme */}
        <button
          onClick={() => setDarkMode(!darkMode)}
          className="flex h-12 w-12 items-center justify-center rounded-2xl bg-slate-100 transition-all duration-300 hover:-translate-y-0.5 hover:shadow-xl hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700"
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
            className="flex items-center gap-3 rounded-2xl border border-slate-200 bg-white px-2 py-2 transition-all duration-300 hover:-translate-y-0.5 hover:shadow-lg hover:bg-slate-100/70 dark:border-slate-700 dark:bg-slate-900"
          >
            <div className="flex h-11 w-11 items-center justify-center rounded-full bg-gradient-to-br from-blue-600 via-indigo-600 to-cyan-500 font-semibold text-white">
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
            <div
  className="
    absolute
    right-0
    mt-3
    w-56
    overflow-hidden
    rounded-3xl
    border
    border-slate-200
    bg-white
    shadow-2xl
    origin-top-right
    duration-200
    dark:border-slate-700
    dark:bg-slate-900
  "
>
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
      </div>
    </header>
  );
};

export default Navbar;