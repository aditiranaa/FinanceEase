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
  PanelLeftClose,
  PanelLeftOpen,
} from "lucide-react";

const Sidebar = ({ collapsed, setCollapsed }) => {
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
      {/* Mobile Menu Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="fixed left-5 top-5 z-50 flex h-11 w-11 items-center justify-center rounded-xl border border-slate-200 bg-white shadow-lg transition hover:bg-slate-50 md:hidden"
      >
        {isOpen ? <X size={20} /> : <Menu size={20} />}
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
          fixed
          left-0
          top-0
          z-40
          flex
          h-screen
          flex-col
          border-r
          border-slate-200
          bg-white
          shadow-xl
          transition-[width,transform]
          duration-300
          ease-in-out
          overflow-hidden

          ${collapsed ? "w-20" : "w-72"}

          ${
            isOpen
              ? "translate-x-0"
              : "-translate-x-full md:translate-x-0"
          }
        `}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-6">
          <div
            className={`flex items-center ${
              collapsed ? "justify-center w-full" : "gap-3"
            }`}
          >
            <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl bg-emerald-600 text-xl font-bold text-white shadow">
              F
            </div>

            {!collapsed && (
              <div className="overflow-hidden">
                <h1 className="truncate text-xl font-bold text-slate-900">
                  FinanceEase
                </h1>

                <p className="text-sm text-slate-500">
                  Personal Finance
                </p>
              </div>
            )}
          </div>

          {!collapsed && (
            <button
              onClick={() => setCollapsed(true)}
              className="hidden h-9 w-9 items-center justify-center rounded-lg transition hover:bg-slate-100 md:flex"
            >
              <PanelLeftClose size={18} />
            </button>
          )}
        </div>

        {/* Collapse Button */}
        {collapsed && (
          <div className="mb-4 flex justify-center">
            <button
              onClick={() => setCollapsed(false)}
              className="hidden h-10 w-10 items-center justify-center rounded-xl transition hover:bg-slate-100 md:flex"
            >
              <PanelLeftOpen size={18} />
            </button>
          </div>
        )}

        {/* Navigation */}
        <nav className="flex-1 space-y-2 px-3">
          {menuItems.map((item) => {
            const Icon = item.icon;

            const active = location.pathname === item.path;

            return (
              <button
                key={item.path}
                title={collapsed ? item.name : ""}
                onClick={() => {
                  navigate(item.path);
                  setIsOpen(false);
                }}
                className={`
                  group
                  relative
                  flex
                  w-full
                  items-center
                  rounded-2xl
                  transition-all
                  duration-200

                  ${
                    collapsed
                      ? "justify-center h-14"
                      : "justify-between px-4 py-3"
                  }

                  ${
                    active
                      ? "bg-emerald-50 text-emerald-700"
                      : "text-slate-600 hover:bg-slate-100"
                  }
                `}
              >
                <div
                  className={`flex items-center ${
                    collapsed ? "" : "gap-4"
                  }`}
                >
                  <div
                    className={`
                      flex
                      h-11
                      w-11
                      items-center
                      justify-center
                      rounded-xl
                      transition-all

                      ${
                        active
                          ? "bg-emerald-600 text-white shadow"
                          : "bg-slate-100 text-slate-600 group-hover:bg-white"
                      }
                    `}
                  >
                    <Icon size={20} />
                  </div>

                  {!collapsed && (
                    <span className="font-semibold">
                      {item.name}
                    </span>
                  )}
                </div>

                {!collapsed && active && (
                  <ChevronRight
                    size={18}
                    className="text-emerald-600"
                  />
                )}
              </button>
            );
          })}
        </nav>

        {/* Footer */}
        {!collapsed && (
          <div className="m-4 rounded-2xl border border-slate-200 bg-slate-50 p-4">
            <div className="flex items-center gap-3">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-emerald-600 text-lg font-bold text-white">
                U
              </div>

              <div>
                <h3 className="font-semibold text-slate-900">
                  Welcome Back
                </h3>

                <p className="text-sm text-slate-500">
                  Manage your finances
                </p>
              </div>
            </div>
          </div>
        )}
      </aside>
    </>
  );
};

export default Sidebar;