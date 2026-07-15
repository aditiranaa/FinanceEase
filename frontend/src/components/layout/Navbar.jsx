import { useState, useRef, useEffect } from "react";
import {
  Bell,
  ChevronDown,
  User,
  LogOut,
  Search,
  Plus,
} from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";

export default function Navbar() {
  const navigate = useNavigate();
  const { logout } = useAuth();

  const [open, setOpen] = useState(false);

  const menuRef = useRef(null);

  useEffect(() => {
    function handleClickOutside(e) {
      if (
        menuRef.current &&
        !menuRef.current.contains(e.target)
      ) {
        setOpen(false);
      }
    }

    document.addEventListener(
      "mousedown",
      handleClickOutside
    );

    return () =>
      document.removeEventListener(
        "mousedown",
        handleClickOutside
      );
  }, []);

  const handleLogout = () => {
    logout();
    navigate("/");
  };

  return (
    <header className="sticky top-0 z-20 mb-8 flex h-20 items-center justify-between rounded-3xl border border-gray-200 bg-white px-8 shadow-sm">
      {/* Left */}
      <div>
        <h1 className="text-3xl font-bold tracking-tight text-gray-900">
          Welcome Back 👋
        </h1>

        <p className="mt-1 text-sm text-gray-500">
          Here's what's happening with your finances today.
        </p>
      </div>

      {/* Right */}
      <div className="flex items-center gap-4">
        {/* Search */}
        <div className="hidden items-center gap-3 rounded-2xl border border-gray-200 bg-gray-50 px-4 py-3 lg:flex">
          <Search
            size={18}
            className="text-gray-400"
          />

          <input
            type="text"
            placeholder="Search..."
            className="w-56 bg-transparent text-sm outline-none placeholder:text-gray-400"
          />
        </div>

        {/* Quick Add */}
        <button className="hidden items-center gap-2 rounded-2xl bg-emerald-600 px-5 py-3 font-semibold text-white transition hover:bg-emerald-700 lg:flex">
          <Plus size={18} />
          Add New
        </button>

        {/* Notifications */}
        <button className="relative rounded-2xl border border-gray-200 bg-white p-3 transition hover:bg-gray-50">
          <Bell
            size={20}
            className="text-gray-600"
          />

          <span className="absolute right-3 top-3 h-2.5 w-2.5 rounded-full border-2 border-white bg-red-500" />
        </button>

        {/* Profile */}
        <div
          className="relative"
          ref={menuRef}
        >
          <button
            onClick={() =>
              setOpen((prev) => !prev)
            }
            className="flex items-center gap-3 rounded-2xl border border-gray-200 bg-white px-3 py-2 transition hover:bg-gray-50"
          >
            <div className="flex h-11 w-11 items-center justify-center rounded-full bg-emerald-600 text-base font-bold text-white">
              U
            </div>

            <div className="hidden text-left md:block">
              <p className="text-sm font-semibold text-gray-900">
                John Doe
              </p>

              <p className="text-xs text-gray-500">
                Personal Account
              </p>
            </div>

            <ChevronDown
              size={18}
              className={`text-gray-500 transition-transform ${
                open ? "rotate-180" : ""
              }`}
            />
          </button>

          {open && (
            <div className="absolute right-0 mt-3 w-60 overflow-hidden rounded-2xl border border-gray-200 bg-white shadow-xl">
              <button
                onClick={() => {
                  navigate("/profile");
                  setOpen(false);
                }}
                className="flex w-full items-center gap-3 px-5 py-4 text-sm font-medium text-gray-700 transition hover:bg-gray-50"
              >
                <User size={18} />
                Profile
              </button>

              <button
                onClick={handleLogout}
                className="flex w-full items-center gap-3 px-5 py-4 text-sm font-medium text-red-600 transition hover:bg-red-50"
              >
                <LogOut size={18} />
                Logout
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}