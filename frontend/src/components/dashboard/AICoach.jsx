import {
  useEffect,
  useState,
} from "react";

import {
  getAISpendingCoach,
} from "../../api/authApi";

const AICoach = () => {

  const [
    coachData,
    setCoachData,
  ] = useState(null);

  const [
    loading,
    setLoading,
  ] = useState(true);

  const [
    error,
    setError,
  ] = useState("");

  useEffect(() => {

    fetchCoach();

  }, []);

  const fetchCoach =
    async () => {

      try {

        const data =
          await getAISpendingCoach();

        console.log(
          "AI Coach Response:",
          data
        );

        setCoachData(data);

      }

      catch (err) {

        console.error(err);

        setError(
          "Unable to load AI Coach."
        );

      }

      finally {

        setLoading(false);

      }

    };

  if (loading) {

    return (

      <div
        className="
          bg-white
          rounded-2xl
          shadow-sm
          p-6
          mt-8
        "
      >

        Loading AI Coach...

      </div>

    );

  }

  if (error) {

    return (

      <div
        className="
          bg-red-50
          border
          border-red-300
          rounded-2xl
          p-6
          mt-8
          text-red-600
        "
      >

        {error}

      </div>

    );

  }

  if (!coachData) {

    return (

      <div
        className="
          bg-white
          rounded-2xl
          shadow-sm
          p-6
          mt-8
        "
      >

        No AI data available.

      </div>

    );

  }

  return (

    <div
      className="
        bg-white
        rounded-2xl
        shadow-sm
        p-6
        mt-8
      "
    >

      <h2
        className="
          text-2xl
          font-bold
          mb-6
        "
      >
        🤖 AI Spending Coach
      </h2>

      <div
        className="
          grid
          grid-cols-2
          gap-4
        "
      >

        <div>

          <p
  className="
    text-gray-500
    dark:text-gray-400
    font-medium
  "
>
            Income
          </p>

          <h3 className="text-xl font-bold">

            ₹
            {
              coachData.summary?.income ??
              0
            }

          </h3>

        </div>

        <div>

          <p
  className="
    text-gray-500
    dark:text-gray-400
    font-medium
  "
>
            Expenses
          </p>

          <h3 className="text-xl font-bold">

            ₹
            {
              coachData.summary?.expenses ??
              0
            }

          </h3>

        </div>

        <div>

          <p
  className="
    text-gray-500
    dark:text-gray-400
    font-medium
  "
>
            Savings
          </p>

          <h3 className="text-xl font-bold">

            ₹
            {
              coachData.summary?.savings ??
              0
            }

          </h3>

        </div>

        <div>

          <p
  className="
    text-gray-500
    dark:text-gray-400
    font-medium
  "
>
            Savings Rate
          </p>

          <h3 className="text-xl font-bold">

            {
              coachData.summary?.savingsRate ??
              0
            }
            %

          </h3>

        </div>

      </div>

      <div
        className="
          mt-5
        "
      >

        <p
  className="
    text-gray-500
    dark:text-gray-400
    font-medium
  "
>

          Highest Spending Category

        </p>

        <h3
          className="
            text-lg
            font-semibold
          "
        >

          {
            coachData.summary
              ?.highestCategory ??
            "None"
          }

        </h3>

      </div>

      <div
        className="
          mt-6
          bg-green-50
          border-l-4
          border-green-500
          rounded-lg
          p-4
        "
      >

        <h3
          className="
            font-semibold
            mb-2
          "
        >
          💡 AI Recommendation
        </h3>

        <p>

          {
            coachData.insight ??
            "No recommendation available."
          }

        </p>

      </div>

    </div>

  );

};

export default AICoach;