import {
  ArrowUpRight,
  ArrowDownLeft,
  Wallet,
  Sparkles,
  TrendingUp,
} from "lucide-react";

const formatCurrency = (value) =>
  Number(value || 0).toLocaleString("en-IN", {
    style: "currency",
    currency: "INR",
    maximumFractionDigits: 0,
  });

export default function HeroBanner({ balance }) {
  const monthGrowth = 12.4;

  return (
    <section className="relative overflow-hidden rounded-[32px] bg-gradient-to-br from-blue-700 via-indigo-700 to-sky-600 p-8 text-white shadow-[0_25px_70px_rgba(37,99,235,.28)] lg:p-10">
      {/* Background Glow */}
      <div className="absolute -right-24 -top-24 h-80 w-80 rounded-full bg-white/10 blur-3xl" />
      <div className="absolute -bottom-32 left-0 h-72 w-72 rounded-full bg-cyan-300/10 blur-3xl" />

      <div className="relative">
        {/* Header */}
        <div className="flex flex-col gap-8 xl:flex-row xl:items-center xl:justify-between">
          {/* Left */}
          <div className="max-w-2xl">
            <div className="inline-flex items-center gap-2 rounded-full border border-white/20 bg-white/10 px-4 py-2 backdrop-blur-xl">
              <Sparkles size={16} />
              <span className="text-sm font-medium">
                Financial Overview
              </span>
            </div>

            <p className="mt-6 text-sm uppercase tracking-[0.25em] text-blue-100">
              Total Balance
            </p>

            <h1 className="mt-3 text-5xl font-black tracking-tight lg:text-6xl">
              {formatCurrency(balance)}
            </h1>

            <div className="mt-5 flex items-center gap-3">
              <div className="flex items-center gap-2 rounded-full bg-emerald-400/20 px-4 py-2 text-sm font-semibold text-emerald-100">
                <TrendingUp size={16} />
                +{monthGrowth}% this month
              </div>

              <div className="rounded-full border border-white/20 bg-white/10 px-4 py-2 text-sm">
                Financial Health • Excellent
              </div>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="flex flex-wrap gap-4">
            <button className="flex items-center gap-2 rounded-2xl bg-white px-6 py-4 font-semibold text-slate-900 transition-all duration-300 hover:-translate-y-1 hover:shadow-2xl">
              <ArrowUpRight size={18} />
              Add Transaction
            </button>

            <button className="flex items-center gap-2 rounded-2xl border border-white/20 bg-white/10 px-6 py-4 font-semibold backdrop-blur-xl transition-all duration-300 hover:bg-white/20">
              <ArrowDownLeft size={18} />
              Transfer
            </button>
          </div>
        </div>

        {/* Summary Cards */}
        <div className="mt-10 grid gap-5 md:grid-cols-2 xl:grid-cols-4">
          <div className="rounded-3xl border border-white/15 bg-white/10 p-6 backdrop-blur-xl">
            <div className="flex items-center justify-between">
              <Wallet size={22} />
              <span className="text-xs text-blue-100">Available</span>
            </div>

            <h3 className="mt-6 text-2xl font-bold">
              {formatCurrency(balance)}
            </h3>

            <p className="mt-2 text-sm text-blue-100">
              Ready to spend
            </p>
          </div>

          <div className="rounded-3xl border border-white/15 bg-white/10 p-6 backdrop-blur-xl">
            <div className="flex items-center justify-between">
              <TrendingUp size={22} />
              <span className="text-xs text-blue-100">
                Cash Flow
              </span>
            </div>

            <h3 className="mt-6 text-2xl font-bold">
              Positive
            </h3>

            <p className="mt-2 text-sm text-blue-100">
              Growing steadily
            </p>
          </div>

          <div className="rounded-3xl border border-white/15 bg-white/10 p-6 backdrop-blur-xl">
            <div className="flex items-center justify-between">
              <Sparkles size={22} />
              <span className="text-xs text-blue-100">
                Savings
              </span>
            </div>

            <h3 className="mt-6 text-2xl font-bold">
              On Track
            </h3>

            <p className="mt-2 text-sm text-blue-100">
              Goal progressing
            </p>
          </div>

          <div className="rounded-3xl border border-white/15 bg-white/10 p-6 backdrop-blur-xl">
            <div className="flex items-center justify-between">
              <TrendingUp size={22} />
              <span className="text-xs text-blue-100">
                Budget
              </span>
            </div>

            <h3 className="mt-6 text-2xl font-bold">
              Healthy
            </h3>

            <p className="mt-2 text-sm text-blue-100">
              No alerts today
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}