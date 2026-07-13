import Navbar from "../../components/layout/Navbar";
import Sidebar from "../../components/layout/Sidebar";

import useAI from "../../hooks/useAI";
import useAnalytics from "../../hooks/useAnalytics";

import AIManager from "./AIManager";

export default function AI() {

  const {
    overview,
    loading: analyticsLoading,
  } = useAnalytics();

  const {
    history,
    analysis,
    loading,
    error,
    analyze,
    removeHistory,
  } = useAI();

  if (analyticsLoading) {
    return (
      <div className="flex justify-center items-center h-screen">
        Loading...
      </div>
    );
  }

  return (
    <div className="flex flex-col md:flex-row">

      <Sidebar />

      <div className="flex-1 bg-gray-100 dark:bg-gray-950 min-h-screen p-6">

        <Navbar />

        <div className="mt-4 space-y-8">

          <div>

            <h1 className="text-3xl font-bold">
              AI Financial Coach
            </h1>

            <p className="text-gray-500 mt-2">
              Get personalized financial insights powered by Gemini AI.
            </p>

          </div>

          {error && (
            <div className="bg-red-100 text-red-700 rounded-lg p-4">
              {error}
            </div>
          )}

          <AIManager
            overview={overview}
            analysis={analysis}
            history={history}
            loading={loading}
            analyze={analyze}
            removeHistory={removeHistory}
          />

        </div>

      </div>

    </div>
  );
}