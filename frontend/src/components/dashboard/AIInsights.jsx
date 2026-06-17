import {
  useState,
} from "react";

import {
  getAIInsight,
} from "../../api/authApi";

const AIInsights = () => {

  const [prompt, setPrompt] =
    useState("");

  const [insight, setInsight] =
    useState("");

  const [loading, setLoading] =
    useState(false);

  const handleAsk =
    async () => {

      try {

        setLoading(true);

        const data =
          await getAIInsight(
            prompt
          );

        setInsight(
          data.insight
        );

      } catch (error) {

        console.log(error);

      }

      setLoading(false);

    };

  return (

    <div
      className="
        bg-white
        p-6
        rounded-2xl
        shadow-sm
        mt-8
      "
    >

      <h2
        className="
          text-2xl
          font-bold
          mb-4
        "
      >
        AI Insights
      </h2>

      <textarea
        rows="4"
        value={prompt}
        onChange={(e) =>
          setPrompt(
            e.target.value
          )
        }
        placeholder="
          Analyze my spending habits
        "
        className="
          w-full
          border
          p-3
          rounded-lg
        "
      />

      <button
        onClick={handleAsk}
        className="
          bg-purple-500
          text-white
          px-5
          py-3
          rounded-lg
          mt-4
        "
      >

        Ask AI

      </button>

      {loading && (

        <p className="mt-4">
          Thinking...
        </p>

      )}

      {insight && (

        <div
          className="
            mt-5
            bg-gray-50
            p-4
            rounded-xl
          "
        >

          {insight}

        </div>

      )}

    </div>

  );

};

export default AIInsights;