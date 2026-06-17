import {
  useEffect,
  useState,
} from "react";

import {
  getGoals,
  createGoal,
} from "../../api/authApi";

const SavingsGoals = () => {

  const [formData, setFormData] =
    useState({
      title: "",
      target_amount: "",
      current_amount: "",
    });

  const [goals, setGoals] =
    useState([]);

  const handleChange = (e) => {

    setFormData({
      ...formData,
      [e.target.name]:
        e.target.value,
    });

  };

  const fetchGoals =
    async () => {

      try {

        const data =
          await getGoals();

        setGoals(data);

      } catch (error) {

        console.log(error);

      }

    };

  useEffect(() => {

    fetchGoals();

  }, []);

  const handleSubmit =
    async (e) => {

      e.preventDefault();

      try {

        await createGoal(
          formData
        );

        await fetchGoals();

        setFormData({
          title: "",
          target_amount: "",
          current_amount: "",
        });

      } catch (error) {

        console.log(error);

      }

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
          mb-6
        "
      >
        Savings Goals
      </h2>

      <form
        onSubmit={handleSubmit}
        className="space-y-4"
      >

        <input
          type="text"
          name="title"
          placeholder="Goal Name"
          value={formData.title}
          onChange={handleChange}
          className="
            w-full
            border
            p-3
            rounded-lg
          "
        />

        <input
          type="number"
          name="target_amount"
          placeholder="Target Amount"
          value={formData.target_amount}
          onChange={handleChange}
          className="
            w-full
            border
            p-3
            rounded-lg
          "
        />

        <input
          type="number"
          name="current_amount"
          placeholder="Current Amount"
          value={formData.current_amount}
          onChange={handleChange}
          className="
            w-full
            border
            p-3
            rounded-lg
          "
        />

        <button
          type="submit"
          className="
            bg-green-500
            text-white
            px-5
            py-3
            rounded-lg
            hover:bg-green-600
          "
        >
          Add Goal
        </button>

      </form>

      <div className="mt-6 space-y-4">

        {goals.length === 0 ? (

          <p className="text-gray-400">
            No goals yet
          </p>

        ) : (

          goals.map((goal) => {

            const percentage =
              Number(
                goal.target_amount
              ) > 0
                ? Math.min(
                    (
                      Number(
                        goal.current_amount
                      ) /
                      Number(
                        goal.target_amount
                      )
                    ) * 100,
                    100
                  )
                : 0;

            return (

              <div
                key={goal.id}
                className="
                  bg-gray-50
                  p-4
                  rounded-xl
                "
              >

                <h3
                  className="
                    font-semibold
                    text-gray-800
                  "
                >
                  {goal.title}
                </h3>

                <p
                  className="
                    text-gray-500
                    mt-1
                  "
                >
                  ₹
                  {Number(
                    goal.current_amount
                  ).toLocaleString(
                    "en-IN"
                  )}
                  {" / "}
                  ₹
                  {Number(
                    goal.target_amount
                  ).toLocaleString(
                    "en-IN"
                  )}
                </p>

                <div
                  className="
                    w-full
                    bg-gray-200
                    h-3
                    rounded-full
                    mt-3
                  "
                >

                  <div
                    className="
                      bg-green-500
                      h-3
                      rounded-full
                    "
                    style={{
                      width:
                        `${percentage}%`,
                    }}
                  />

                </div>

                <p
                  className="
                    text-sm
                    text-gray-500
                    mt-2
                  "
                >
                  {percentage.toFixed(
                    0
                  )}
                  % Complete
                </p>

              </div>

            );

          })

        )}

      </div>

    </div>

  );

};

export default SavingsGoals;