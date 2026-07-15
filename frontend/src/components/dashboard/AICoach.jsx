import {
  useEffect,
  useState,
} from "react";

import {
  Brain,
  TrendingUp,
  TrendingDown,
  PiggyBank,
  Target,
  Sparkles,
  AlertCircle,
} from "lucide-react";

import {
  getAISpendingCoach,
} from "../../api/authApi";

const formatCurrency = (value) =>
  Number(value || 0).toLocaleString("en-IN", {
    style: "currency",
    currency: "INR",
    maximumFractionDigits: 0,
  });

function StatCard({
  title,
  value,
  icon: Icon,
  color,
}) {
  return (
    <div className="rounded-2xl border border-gray-100 bg-gray-50 p-4">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-500">
            {title}
          </p>

          <h3 className="mt-2 text-2xl font-bold text-gray-900">
            {value}
          </h3>
        </div>

        <div
          className={`flex h-12 w-12 items-center justify-center rounded-xl ${color}`}
        >
          <Icon
            size={22}
            className="text-white"
          />
        </div>
      </div>
    </div>
  );
}

export default function AICoach() {
  const [coachData, setCoachData] =
    useState(null);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState("");

  useEffect(() => {
    fetchCoach();
  }, []);

  const fetchCoach = async () => {
    try {
      const data =
        await getAISpendingCoach();

      setCoachData(data);
    } catch (err) {
      console.error(err);

      setError(
        "Unable to load AI Coach."
      );
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <section className="rounded-3xl border border-gray-200 bg-white p-7 shadow-sm">
        <div className="animate-pulse space-y-5">
          <div className="h-7 w-48 rounded bg-gray-200" />

          <div className="grid grid-cols-2 gap-4">
            {[1, 2, 3, 4].map((i) => (
              <div
                key={i}
                className="h-24 rounded-2xl bg-gray-200"
              />
            ))}
          </div>

          <div className="h-32 rounded-2xl bg-gray-200" />
        </div>
      </section>
    );
  }

  if (error) {
    return (
      <section className="rounded-3xl border border-red-200 bg-red-50 p-7 shadow-sm">
        <div className="flex items-center gap-3">
          <AlertCircle className="text-red-500" />

          <p className="font-medium text-red-600">
            {error}
          </p>
        </div>
      </section>
    );
  }

  if (!coachData) {
    return (
      <section className="rounded-3xl border border-gray-200 bg-white p-7 text-center shadow-sm">
        No AI data available.
      </section>
    );
  }

  const summary =
    coachData.summary || {};

  return (
    <section className="rounded-3xl border border-gray-200 bg-white p-7 shadow-sm">
      <div className="mb-8 flex items-center gap-4">
        <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-violet-100">
          <Brain
            size={30}
            className="text-violet-600"
          />
        </div>

        <div>
          <h2 className="text-2xl font-bold text-gray-900">
            AI Spending Coach
          </h2>

          <p className="mt-1 text-sm text-gray-500">
            Personalized financial insights based on your activity.
          </p>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <StatCard
          title="Income"
          value={formatCurrency(
            summary.income
          )}
          icon={TrendingUp}
          color="bg-emerald-500"
        />

        <StatCard
          title="Expenses"
          value={formatCurrency(
            summary.expenses
          )}
          icon={TrendingDown}
          color="bg-red-500"
        />

        <StatCard
          title="Savings"
          value={formatCurrency(
            summary.savings
          )}
          icon={PiggyBank}
          color="bg-blue-500"
        />

        <StatCard
          title="Savings Rate"
          value={`${summary.savingsRate || 0}%`}
          icon={Target}
          color="bg-amber-500"
        />
      </div>

      <div className="mt-8 rounded-2xl border border-gray-100 bg-gray-50 p-5">
        <p className="text-sm font-medium text-gray-500">
          Highest Spending Category
        </p>

        <h3 className="mt-2 text-xl font-bold text-gray-900">
          {summary.highestCategory ||
            "No data available"}
        </h3>
      </div>

      <div className="mt-8 rounded-2xl bg-gradient-to-r from-violet-600 to-indigo-600 p-6 text-white">
        <div className="mb-4 flex items-center gap-2">
          <Sparkles size={20} />

          <h3 className="text-lg font-semibold">
            AI Recommendation
          </h3>
        </div>

        <p className="leading-8 text-violet-100">
          {coachData.insight ||
            "No recommendation available."}
        </p>
      </div>
    </section>
  );
}