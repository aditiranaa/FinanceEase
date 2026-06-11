import {
  useState,
} from "react";

import {
  getAIInsight,
} from "../../api/authApi";

const AIInsights = () => {

  const [insight, setInsight] =
    useState("");

  const [loading, setLoading] =
    useState(false);

  const fetchInsight =
    async () => {

      try {

        setLoading(true);

        const data =
          await getAIInsight();

        setInsight(
          data.text
        );

      } catch (error) {

        console.log(error);

      } finally {

        setLoading(false);

      }

    };

  return (

    <div
      className="
        bg-white
        rounded-2xl
        p-6
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

      <button
        onClick={fetchInsight}
        className="
          bg-purple-600
          text-white
          px-5
          py-3
          rounded-lg
          hover:bg-purple-700
        "
      >
        Generate Insight
      </button>

      {loading && (

        <p className="mt-4">
          Loading...
        </p>

      )}

      {insight && (

        <div
          className="
            mt-6
            bg-purple-50
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