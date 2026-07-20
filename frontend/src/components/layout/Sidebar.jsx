import { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import {
  LayoutDashboard,
  Receipt,
  Wallet,
  Target,
  User,
  BarChart3,
  Bell,
  Sparkles,
  Settings,
  Menu,
  X,
  PanelLeftClose,
  PanelLeftOpen,
  ChevronRight,
} from "lucide-react";

const navigation = [
  {
    title: "MAIN",
    items: [
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
    ],
  },

  {
    title: "INSIGHTS",
    items: [
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
        name: "AI Assistant",
        path: "/ai",
        icon: Sparkles,
      },
    ],
  },

  {
    title: "ACCOUNT",
    items: [
      {
        name: "Profile",
        path: "/profile",
        icon: User,
      },
      {
        name: "Notifications",
        path: "/notifications",
        icon: Bell,
      },
      {
        name: "Settings",
        path: "/settings",
        icon: Settings,
      },
    ],
  },
];

export default function Sidebar({
  collapsed,
  setCollapsed,
}) {
  const navigate = useNavigate();
  const location = useLocation();

  const [isOpen, setIsOpen] = useState(false);

  return (
    <>
      {/* Mobile Button */}

      <button
        onClick={() => setIsOpen(!isOpen)}
        className="fixed left-6 top-6 z-50 flex h-12 w-12 items-center justify-center rounded-2xl border border-white/40 bg-white/80 shadow-xl backdrop-blur-xl md:hidden"
      >
        {isOpen ? <X size={20} /> : <Menu size={20} />}
      </button>

      {/* Overlay */}

      {isOpen && (
        <div
          onClick={() => setIsOpen(false)}
          className="fixed inset-0 z-40 bg-black/30 backdrop-blur-sm md:hidden"
        />
      )}

      <aside
        className={`
          fixed
          left-5
          top-5
          bottom-5
          z-50

          flex
          flex-col

          overflow-hidden

          rounded-[30px]

          border
          border-white/40

          bg-white/80

          backdrop-blur-2xl

          shadow-[0_20px_60px_rgba(15,23,42,.10)]

          transition-all
          duration-500

          ${
            collapsed
              ? "w-24"
              : "w-[310px]"
          }

          ${
            isOpen
              ? "translate-x-0"
              : "-translate-x-[120%] md:translate-x-0"
          }
        `}
      >
                {/* Logo */}

        <div className="px-7 pt-8 pb-6">

          <div
            className={`flex items-center ${
              collapsed ? "justify-center" : "gap-4"
            }`}
          >
            <div
              className="
                flex
                h-14
                w-14
                items-center
                justify-center
                rounded-3xl
                bg-gradient-to-br
                from-blue-600
                via-indigo-600
                to-cyan-500
                text-xl
                font-black
                text-white
                shadow-lg
              "
            >
              F
            </div>

            {!collapsed && (
              <div>

                <h2 className="text-[22px] font-bold tracking-tight text-slate-900">
                  FinanceEase
                </h2>

                <p className="mt-1 text-sm text-slate-500">
                  Smart Finance Platform
                </p>

              </div>
            )}
          </div>
        </div>

        {/* Collapse Button */}

        <div className="px-5">

          <button
            onClick={() => setCollapsed(!collapsed)}
            className="
              hidden
              md:flex
              w-full
              items-center
              justify-center
              rounded-2xl
              border
              border-slate-200
              bg-slate-50
              py-3
              transition-all
              duration-300
              hover:bg-slate-100
            "
          >
            {collapsed ? (
              <PanelLeftOpen size={18} />
            ) : (
              <PanelLeftClose size={18} />
            )}
          </button>

        </div>

        {/* Balance Card */}

        {!collapsed && (

          <div className="mx-5 mt-6">

            <div className="rounded-[28px] bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 p-6 text-white shadow-xl">

              <p className="text-xs uppercase tracking-[0.25em] text-slate-400">
                Total Balance
              </p>

              <h2 className="mt-3 text-3xl font-bold">
                ₹2,45,780
              </h2>

              <div className="mt-3 inline-flex items-center rounded-full bg-emerald-500/20 px-3 py-1 text-sm font-medium text-emerald-300">
                ↑ 12.8% this month
              </div>

            </div>

          </div>

        )}

        {/* Navigation */}

        <div className="mt-8 flex-1 overflow-y-auto px-4 space-y-8">

                    {navigation.map((section) => (
            <div key={section.title}>

              {!collapsed && (
                <h4 className="mb-3 px-3 text-xs font-bold uppercase tracking-[0.25em] text-slate-400">
                  {section.title}
                </h4>
              )}

              <div className="space-y-2">

                {section.items.map((item) => {

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
                      title={collapsed ? item.name : ""}
                      className={`
                        group
                        relative
                        flex
                        w-full
                        items-center

                        rounded-2xl

                        transition-all
                        duration-300

                        ${
                          collapsed
                            ? "justify-center h-14"
                            : "justify-between px-4 py-3"
                        }

                        ${
                          active
                            ? "bg-gradient-to-r from-blue-600 to-indigo-600 text-white shadow-xl shadow-blue-500/20"
                            : "text-slate-600 hover:bg-white hover:shadow-md"
                        }
                      `}
                    >

                      {active && (

                        <div
                          className="
                            absolute
                            left-0
                            top-3
                            bottom-3
                            w-1
                            rounded-r-full
                            bg-cyan-300
                          "
                        />

                      )}

                      <div
                        className={`flex items-center ${
                          collapsed ? "" : "gap-4"
                        }`}
                      >

                        <div
                          className={`
                            relative

                            flex
                            h-11
                            w-11
                            items-center
                            justify-center

                            rounded-xl

                            transition-all
                            duration-300

                            ${
                              active
                                ? "bg-white/15"
                                : "bg-slate-100 group-hover:bg-blue-50"
                            }
                          `}
                        >

                          <Icon size={20} />

                          {item.name === "Notifications" && !collapsed && (
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
                          )}

                        </div>

                        {!collapsed && (

                          <span className="font-semibold">

                            {item.name}

                          </span>

                        )}

                      </div>

                      {!collapsed && item.name === "AI Assistant" && (

                        <span
                          className="
                            rounded-full
                            bg-violet-100
                            px-2
                            py-1
                            text-[11px]
                            font-semibold
                            text-violet-700
                          "
                        >
                          AI
                        </span>

                      )}

                      {!collapsed && active && (

                        <ChevronRight
                          size={18}
                          className="opacity-90"
                        />

                      )}

                    </button>

                  );

                })}

              </div>

            </div>
          ))}
                  </div>

        {/* Bottom Profile */}

        <div className="border-t border-slate-200/70 p-5">

          {!collapsed ? (

            <div className="rounded-3xl bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 p-5 text-white shadow-xl">

              <div className="flex items-center gap-4">

                <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-blue-500 to-cyan-400 text-lg font-bold">

                  A

                </div>

                <div className="flex-1">

                  <h3 className="font-semibold">
                    Alex Johnson
                  </h3>

                  <p className="text-sm text-slate-300">
                    Premium Member
                  </p>

                </div>

              </div>

              <button
                className="
                  mt-5
                  w-full
                  rounded-2xl
                  bg-white/10
                  py-3
                  font-medium
                  transition-all
                  duration-300
                  hover:bg-white/20
                "
              >
                Manage Account
              </button>

            </div>

          ) : (

            <div className="flex justify-center">

              <button
                className="
                  flex
                  h-14
                  w-14
                  items-center
                  justify-center
                  rounded-2xl
                  bg-gradient-to-br
                  from-blue-600
                  to-cyan-500
                  text-lg
                  font-bold
                  text-white
                  shadow-lg
                  transition-transform
                  duration-300
                  hover:scale-105
                "
              >
                A
              </button>

            </div>

          )}

        </div>

      </aside>

    </>

  );

}