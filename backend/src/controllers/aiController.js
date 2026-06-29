const { GoogleGenAI } =
require("@google/genai");

const knex =
require("../config/db");

const {
  v4: uuidv4,
} = require("uuid");

const ai =
new GoogleGenAI({
  apiKey:
    process.env.GEMINI_API_KEY,
});

exports.getAIHistory =
async (req, res) => {

  try {

    const history =
      await knex(
        "ai_history"
      )
      .where({

        user_id:
          req.user.id,

      })
      .orderBy(
        "created_at",
        "desc"
      );

    res.json(
      history
    );

  }

  catch (error) {

    res.status(500).json({

      error:
        error.message,

    });

  }

};

exports.getAIInsight =
async (req, res) => {

  try {

    const { prompt } =
      req.body;

    const response =
      await ai.models.generateContent({

        model:
          "gemini-2.5-flash",

        contents:
          prompt,

      });

    await knex(
      "ai_history"
    ).insert({

      id:
        uuidv4(),

      user_id:
        req.user.id,

      prompt,

      response:
        response.text,

    });

    res.json({

      insight:
        response.text,

    });

  }

  catch (error) {

    res.status(500).json({

      message:
        "AI Error",

    });

  }

};

exports.getAISpendingCoach =
async (req, res) => {

  try {

    const transactions =
      await knex(
        "transactions"
      )
      .where({

        user_id:
          req.user.id,

      });

    let income = 0;

    let expenses = 0;

    const categories = {};

    transactions.forEach(
      (transaction) => {

        const amount =
          Number(
            transaction.amount
          );

        if (amount > 0) {

          income += amount;

        }

        else {

          expenses +=
            Math.abs(amount);

        }

        categories[
          transaction.category
        ] =

        (

          categories[
            transaction.category
          ]

          ||

          0

        )

        +

        Math.abs(amount);

      }
    );

    const highestCategory =
      Object.entries(
        categories
      )
      .sort(
        (a, b) =>
          b[1] - a[1]
      )[0];

    const savings =
      income - expenses;

    const savingsRate =
      income > 0

        ?

        (
          (
            savings /
            income
          ) * 100
        ).toFixed(1)

        :

        0;

    const prompt =

`
You are an expert personal finance advisor.

Analyze this financial data.

Income:
₹${income}

Expenses:
₹${expenses}

Savings:
₹${savings}

Savings Rate:
${savingsRate}%

Highest Spending Category:
${highestCategory?.[0] || "None"}

Category Amount:
₹${highestCategory?.[1] || 0}

Provide:

1. Spending analysis.

2. Savings advice.

3. Budget recommendation.

4. One practical financial tip.

Keep the response under 150 words.
`;

    const response =
      await ai.models.generateContent({

        model:
          "gemini-2.5-flash",

        contents:
          prompt,

      });

    res.json({

      insight:
        response.text,

      summary: {

        income,

        expenses,

        savings,

        savingsRate,

        highestCategory:
          highestCategory?.[0] || "None",

        highestCategoryAmount:
          highestCategory?.[1] || 0,

      },

    });

  }

  catch (error) {

    res.status(500).json({

      error:
        error.message,

    });

  }

};