import { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import {
  LayoutDashboard,
  Receipt,
  Wallet,
  Target,
  User,
  BarChart3,
  Menu,
  X,
  ChevronRight,
} from "lucide-react";

const Sidebar = () => {
  const [isOpen, setIsOpen] = useState(false);

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
      {/* Mobile Toggle */}
      <button
        onClick={() => setIsOpen((prev) => !prev)}
        className="fixed left-5 top-5 z-50 rounded-xl border border-gray-200 bg-white p-2 shadow-lg md:hidden"
      >
        {isOpen ? <X size={22} /> : <Menu size={22} />}
      </button>

      {/* Overlay */}
      {isOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/40 backdrop-blur-sm md:hidden"
          onClick={() => setIsOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`
          fixed left-0 top-0 z-40 flex h-screen w-72 flex-col
          border-r border-gray-200
          bg-white
          px-6 py-8
          shadow-xl
          transition-transform duration-300

          ${
            isOpen
              ? "translate-x-0"
              : "-translate-x-full"
          }

          md:translate-x-0
        `}
      >
        {/* Logo */}
        <div>
          <div className="flex items-center gap-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-emerald-600 text-xl font-bold text-white shadow-sm">
              F
            </div>

            <div>
              <h1 className="text-2xl font-bold tracking-tight text-gray-900">
                FinanceEase
              </h1>

              <p className="text-sm text-gray-500">
                Personal Finance
              </p>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="mt-12 flex-1 space-y-2">
          {menuItems.map((item) => {
            const Icon = item.icon;

            const active =
              location.pathname === item.path;

            return (
              <button
                key={item.path}
                onClick={() => {
                  navigate(item.path);
                  setIsOpen(false);
                }}
                className={`
                  group
                  flex
                  w-full
                  items-center
                  justify-between
                  rounded-2xl
                  px-4
                  py-4
                  text-left
                  transition-all
                  duration-200

                  ${
                    active
                      ? "bg-emerald-50 text-emerald-700 shadow-sm"
                      : "text-gray-600 hover:bg-gray-100"
                  }
                `}
              >
                <div className="flex items-center gap-4">
                  <div
                    className={`
                      flex h-11 w-11 items-center justify-center rounded-xl

                      ${
                        active
                          ? "bg-emerald-600 text-white"
                          : "bg-gray-100 text-gray-600 group-hover:bg-white"
                      }
                    `}
                  >
                    <Icon size={21} />
                  </div>

                  <span className="text-[16px] font-semibold">
                    {item.name}
                  </span>
                </div>

                {active && (
                  <ChevronRight
                    size={18}
                    className="text-emerald-600"
                  />
                )}
              </button>
            );
          })}
        </nav>

        {/* Bottom User Card */}
        <div className="rounded-2xl border border-gray-200 bg-gray-50 p-4">
          <div className="flex items-center gap-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-emerald-600 text-lg font-bold text-white">
              U
            </div>

            <div>
              <h3 className="font-semibold text-gray-900">
                Welcome Back
              </h3>

              <p className="text-sm text-gray-500">
                Manage your finances
              </p>
            </div>
          </div>
        </div>
      </aside>
    </>
  );
};

export default Sidebar;