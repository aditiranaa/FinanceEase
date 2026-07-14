import { Bot } from "lucide-react";

export default function AIOverview({
  analysis,
}) {
  return (
    <div className="bg-white dark:bg-gray-900 rounded-xl shadow p-4">

      <div className="flex items-center gap-3 mb-4">
        <Bot className="text-blue-600" />

        <h2 className="text-lg font-bold">
          AI Financial Analysis
        </h2>
      </div>

      {analysis ? (
        <div className="whitespace-pre-wrap text-gray-700 dark:text-gray-300 leading-7">
          {analysis}
        </div>
      ) : (
        <p className="text-gray-500">
          Generate an AI analysis to receive
          personalized financial insights.
        </p>
      )}

    </div>
  );
}