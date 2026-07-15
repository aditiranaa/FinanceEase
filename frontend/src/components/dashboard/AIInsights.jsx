import { useState } from "react";
import {
  Sparkles,
  Brain,
  Send,
} from "lucide-react";

import {
  getAIInsight,
} from "../../api/authApi";

export default function AIInsights() {
  const [prompt, setPrompt] =
    useState("");

  const [insight, setInsight] =
    useState("");

  const [loading, setLoading] =
    useState(false);

  const suggestions = [
    "Analyze my spending habits",
    "Where can I reduce expenses?",
    "Create a monthly budget",
    "How can I save more money?",
  ];

  const handleAsk = async () => {
    if (!prompt.trim()) return;

    try {
      setLoading(true);

      const data =
        await getAIInsight(prompt);

      setInsight(data.insight);
    } catch (error) {
      console.log(error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="rounded-3xl border border-gray-200 bg-white p-8 shadow-sm">
      <div className="mb-8 flex items-center gap-4">
        <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-violet-100">
          <Brain
            className="text-violet-600"
            size={30}
          />
        </div>

        <div>
          <h2 className="text-2xl font-bold text-gray-900">
            AI Financial Advisor
          </h2>

          <p className="mt-1 text-sm text-gray-500">
            Get personalized insights about your finances.
          </p>
        </div>
      </div>

      <div className="mb-6 flex flex-wrap gap-3">
        {suggestions.map((item) => (
          <button
            key={item}
            type="button"
            onClick={() => setPrompt(item)}
            className="rounded-full border border-gray-200 bg-gray-50 px-4 py-2 text-sm font-medium text-gray-700 transition hover:border-violet-300 hover:bg-violet-50 hover:text-violet-700"
          >
            {item}
          </button>
        ))}
      </div>

      <textarea
        rows={5}
        value={prompt}
        onChange={(e) =>
          setPrompt(e.target.value)
        }
        placeholder="Ask FinanceEase AI anything about your finances..."
        className="w-full rounded-2xl border border-gray-200 bg-gray-50 p-5 text-gray-900 outline-none transition focus:border-violet-500 focus:bg-white focus:ring-4 focus:ring-violet-100"
      />

      <button
        onClick={handleAsk}
        disabled={loading}
        className="mt-6 flex h-12 items-center justify-center gap-2 rounded-xl bg-violet-600 px-6 font-semibold text-white transition hover:bg-violet-700 disabled:cursor-not-allowed disabled:opacity-60"
      >
        <Sparkles size={18} />

        {loading
          ? "Analyzing..."
          : "Generate Insight"}

        {!loading && (
          <Send size={17} />
        )}
      </button>

      <div className="mt-8 rounded-2xl border border-gray-100 bg-gradient-to-br from-gray-50 to-white p-6">
        <div className="mb-4 flex items-center gap-2">
          <Sparkles
            size={18}
            className="text-violet-600"
          />

          <h3 className="font-semibold text-gray-900">
            AI Response
          </h3>
        </div>

        {loading ? (
          <div className="space-y-3">
            <div className="h-4 w-full animate-pulse rounded bg-gray-200" />
            <div className="h-4 w-5/6 animate-pulse rounded bg-gray-200" />
            <div className="h-4 w-3/4 animate-pulse rounded bg-gray-200" />
          </div>
        ) : insight ? (
          <p className="whitespace-pre-wrap leading-8 text-gray-700">
            {insight}
          </p>
        ) : (
          <div className="py-10 text-center">
            <Brain
              size={42}
              className="mx-auto mb-4 text-gray-300"
            />

            <p className="text-gray-500">
              Your AI financial recommendations will appear here.
            </p>
          </div>
        )}
      </div>
    </section>
  );
}