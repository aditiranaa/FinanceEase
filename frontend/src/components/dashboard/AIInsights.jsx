import { useState } from "react";
import {
  Brain,
  Sparkles,
  ArrowRight,
  TrendingDown,
  PiggyBank,
  Target,
  RefreshCw,
} from "lucide-react";

import { getAIInsight } from "../../api/authApi";

const quickPrompts = [
  {
    label: "Spending",
    prompt: "Analyze my spending habits",
  },
  {
    label: "Budget",
    prompt: "Create a monthly budget",
  },
  {
    label: "Savings",
    prompt: "How can I save more money?",
  },
  {
    label: "Subscriptions",
    prompt: "Where can I reduce expenses?",
  },
];

export default function AIInsights() {
  const [loading, setLoading] = useState(false);
  const [selectedPrompt, setSelectedPrompt] = useState("");
  const [insight, setInsight] = useState("");

  const fetchInsight = async (prompt) => {
    try {
      setLoading(true);
      setSelectedPrompt(prompt);

      const data = await getAIInsight(prompt);

      setInsight(data?.insight || "");
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="overflow-hidden rounded-[32px] border border-slate-200 bg-white shadow-sm">

      {/* Header */}

      <div className="border-b border-slate-100 p-8">

        <div className="flex items-start justify-between">

          <div className="flex items-center gap-5">

            <div className="flex h-16 w-16 items-center justify-center rounded-3xl bg-gradient-to-br from-blue-600 to-indigo-600 shadow-lg shadow-blue-500/20">

              <Brain
                size={30}
                className="text-white"
              />

            </div>

            <div>

              <div className="inline-flex items-center gap-2 rounded-full bg-blue-50 px-4 py-2 text-sm font-semibold text-blue-700">

                <Sparkles size={15} />

                AI Powered

              </div>

              <h2 className="mt-4 text-3xl font-bold tracking-tight text-slate-900">
                Financial Insights
              </h2>

              <p className="mt-2 text-slate-500">
                Personalized recommendations based on your latest financial activity.
              </p>

            </div>

          </div>

          <button
            onClick={() =>
              selectedPrompt &&
              fetchInsight(selectedPrompt)
            }
            disabled={loading || !selectedPrompt}
            className="flex h-12 w-12 items-center justify-center rounded-2xl border border-slate-200 text-slate-600 transition hover:border-blue-200 hover:bg-blue-50 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <RefreshCw
              size={18}
              className={loading ? "animate-spin" : ""}
            />
          </button>

        </div>

      </div>

      {/* Quick Overview */}

      <div className="grid gap-4 border-b border-slate-100 p-8 md:grid-cols-3">

        <div className="rounded-3xl bg-blue-50 p-5">

          <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-blue-100">

            <TrendingDown
              size={20}
              className="text-blue-600"
            />

          </div>

          <h3 className="mt-5 font-bold text-slate-900">
            Spending Analysis
          </h3>

          <p className="mt-2 text-sm leading-6 text-slate-500">
            Discover where most of your money goes and identify opportunities to spend smarter.
          </p>

        </div>

        <div className="rounded-3xl bg-emerald-50 p-5">

          <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-emerald-100">

            <PiggyBank
              size={20}
              className="text-emerald-600"
            />

          </div>

          <h3 className="mt-5 font-bold text-slate-900">
            Savings Tips
          </h3>

          <p className="mt-2 text-sm leading-6 text-slate-500">
            AI continuously looks for realistic ways to improve your monthly savings.
          </p>

        </div>

        <div className="rounded-3xl bg-violet-50 p-5">

          <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-violet-100">

            <Target
              size={20}
              className="text-violet-600"
            />

          </div>

          <h3 className="mt-5 font-bold text-slate-900">
            Goal Tracking
          </h3>

          <p className="mt-2 text-sm leading-6 text-slate-500">
            Monitor your progress and receive recommendations to reach goals faster.
          </p>

        </div>

      </div>

      {/* Quick Ask */}

      <div className="p-8">

        <div className="mb-6">

          <h3 className="text-lg font-bold text-slate-900">
            Quick Insights
          </h3>

          <p className="mt-2 text-sm text-slate-500">
            Ask FinanceEase AI with one tap.
          </p>

        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          {quickPrompts.map((item) => (
            <button
              key={item.label}
              onClick={() => fetchInsight(item.prompt)}
              disabled={loading}
              className="group flex items-center justify-between rounded-2xl border border-slate-200 bg-white p-5 text-left transition-all duration-300 hover:-translate-y-1 hover:border-blue-200 hover:bg-blue-50 hover:shadow-lg"
            >
              <div>

                <p className="font-semibold text-slate-900">
                  {item.label}
                </p>

                <p className="mt-1 text-sm text-slate-500">
                  {item.prompt}
                </p>

              </div>

              <ArrowRight
                size={18}
                className="text-slate-400 transition group-hover:translate-x-1 group-hover:text-blue-600"
              />

            </button>
          ))}
        </div>

                <div className="mt-8">
          {loading ? (
            <div className="rounded-3xl border border-slate-200 bg-slate-50 p-10 text-center">
              <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-blue-100">
                <RefreshCw
                  size={26}
                  className="animate-spin text-blue-600"
                />
              </div>

              <h3 className="mt-6 text-xl font-semibold text-slate-900">
                AI is analyzing your finances...
              </h3>

              <p className="mt-2 text-sm text-slate-500">
                Looking for spending patterns, savings opportunities and useful
                recommendations.
              </p>
            </div>
          ) : insight ? (
            <div className="overflow-hidden rounded-3xl border border-blue-100 bg-gradient-to-br from-blue-50 via-white to-indigo-50">
              <div className="flex items-center justify-between border-b border-blue-100 px-8 py-6">
                <div className="flex items-center gap-4">
                  <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-blue-600">
                    <Brain className="text-white" size={24} />
                  </div>

                  <div>
                    <p className="text-sm font-medium text-blue-600">
                      AI Recommendation
                    </p>

                    <h3 className="text-xl font-bold text-slate-900">
                      Personalized Insight
                    </h3>
                  </div>
                </div>

                <button
                  onClick={() => fetchInsight(selectedPrompt)}
                  className="rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 transition hover:border-blue-300 hover:text-blue-600"
                >
                  Regenerate
                </button>
              </div>

              <div className="px-8 py-7">
                <p className="whitespace-pre-wrap leading-8 text-slate-700">
                  {insight}
                </p>
              </div>

              <div className="border-t border-blue-100 bg-white/70 px-8 py-5">
                <button className="group flex items-center gap-2 font-semibold text-blue-600 transition hover:gap-3">
                  Open AI Assistant
                  <ArrowRight
                    size={18}
                    className="transition group-hover:translate-x-1"
                  />
                </button>
              </div>
            </div>
          ) : (
            <div className="rounded-3xl border-2 border-dashed border-slate-200 bg-slate-50 px-10 py-16 text-center">
              <div className="mx-auto flex h-20 w-20 items-center justify-center rounded-full bg-blue-100">
                <Brain
                  size={34}
                  className="text-blue-600"
                />
              </div>

              <h3 className="mt-6 text-2xl font-bold text-slate-900">
                Ready for AI Insights
              </h3>

              <p className="mx-auto mt-3 max-w-md text-slate-500">
                Choose one of the quick prompts above and FinanceEase AI will
                analyze your transactions to generate personalized financial
                recommendations.
              </p>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

          