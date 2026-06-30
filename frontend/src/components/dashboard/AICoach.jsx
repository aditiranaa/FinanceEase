import {
  useEffect,
  useState,
} from "react";

import {
  getAISpendingCoach,
} from "../../api/authApi";

const AICoach = () => {

  const [coachData,
    setCoachData] =
    useState(null);

  const [loading,
    setLoading] =
    useState(true);

  useEffect(() => {

    fetchCoach();

  }, []);

  const fetchCoach =
    async () => {

      try {

        const data =
          await getAISpendingCoach();

        setCoachData(data);

      }

      catch (error) {

        console.log(error);

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
          mb-5
        "
      >
        🤖 AI Spending Coach
      </h2>

      <div className="space-y-2">

        <p>

          <strong>
            Income:
          </strong>

          {" "}
          ₹
          {
            coachData.summary.income
          }

        </p>

        <p>

          <strong>
            Expenses:
          </strong>

          {" "}
          ₹
          {
            coachData.summary.expenses
          }

        </p>

        <p>

          <strong>
            Savings:
          </strong>

          {" "}
          ₹
          {
            coachData.summary.savings
          }

        </p>

        <p>

          <strong>
            Savings Rate:
          </strong>

          {" "}
          {
            coachData.summary.savingsRate
          }
          %

        </p>

        <p>

          <strong>
            Highest Spending:
          </strong>

          {" "}
          {
            coachData.summary.highestCategory
          }

        </p>

      </div>

      <div
        className="
          mt-6
          bg-green-50
          border-l-4
          border-green-500
          p-4
          rounded
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
            coachData.insight
          }

        </p>

      </div>

    </div>

  );

};

export default AICoach;