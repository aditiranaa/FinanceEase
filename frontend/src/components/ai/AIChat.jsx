import { Sparkles } from "lucide-react";

export default function AIChat({
  analyze,
  loading,
}) {
  return (
    <div className="bg-white dark:bg-gray-900 rounded-xl shadow p-6">

      <div className="flex items-center justify-between">

        <div>

          <h2 className="text-xl font-bold">
            AI Coach
          </h2>

          <p className="text-gray-500">
            Generate personalized financial advice.
          </p>

        </div>

        <button
          onClick={analyze}
          disabled={loading}
          className="bg-blue-600 hover:bg-blue-700 text-white px-5 py-3 rounded-lg flex items-center gap-2"
        >
          <Sparkles size={18} />

          {loading
            ? "Analyzing..."
            : "Generate"}
        </button>

      </div>

    </div>
  );
}