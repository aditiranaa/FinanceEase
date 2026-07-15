import {
  ArrowUpRight,
  Wallet,
  TrendingUp,
} from "lucide-react";

const formatCurrency = (value) =>
  Number(value || 0).toLocaleString("en-IN", {
    style: "currency",
    currency: "INR",
    maximumFractionDigits: 0,
  });

export default function HeroBanner({
  balance,
}) {
  return (
    <section className="relative overflow-hidden rounded-3xl bg-gradient-to-br from-emerald-600 via-emerald-500 to-teal-500 p-8 text-white shadow-xl lg:p-10">
      {/* Decorative Background */}
      <div className="absolute -right-24 -top-24 h-72 w-72 rounded-full bg-white/10 blur-3xl" />
      <div className="absolute -bottom-28 left-0 h-60 w-60 rounded-full bg-white/10 blur-3xl" />

      <div className="relative flex flex-col gap-10 lg:flex-row lg:items-center lg:justify-between">
        {/* Left Side */}
        <div className="max-w-2xl">
          <div className="mb-6 inline-flex items-center gap-2 rounded-full bg-white/15 px-4 py-2 text-sm font-medium backdrop-blur-md">
            <TrendingUp size={16} />
            Financial Overview
          </div>

          <h1 className="text-4xl font-bold tracking-tight lg:text-5xl">
            Welcome back 👋
          </h1>

          <p className="mt-5 max-w-xl text-lg leading-8 text-emerald-50">
            Stay on top of your finances with real-time insights,
            smarter budgeting, and complete visibility into your
            income, expenses, and savings.
          </p>
        </div>

        {/* Balance Card */}
        <div className="w-full max-w-sm rounded-3xl border border-white/20 bg-white/15 p-7 backdrop-blur-xl">
          <div className="flex items-center justify-between">
            <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-white/20">
              <Wallet size={28} />
            </div>

            <div className="flex items-center gap-2 rounded-full bg-emerald-400/20 px-3 py-1 text-sm font-medium">
              <ArrowUpRight size={15} />
              Healthy
            </div>
          </div>

          <p className="mt-8 text-sm uppercase tracking-[0.2em] text-emerald-100">
            Current Balance
          </p>

          <h2 className="mt-3 text-5xl font-extrabold tracking-tight">
            {formatCurrency(balance)}
          </h2>

          <div className="mt-8 flex items-center justify-between border-t border-white/15 pt-6">
            <div>
              <p className="text-sm text-emerald-100">
                Financial Status
              </p>

              <p className="mt-1 font-semibold">
                Keep Growing 🚀
              </p>
            </div>

            <div className="rounded-2xl bg-white/15 px-4 py-2 text-sm font-medium">
              Live
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}