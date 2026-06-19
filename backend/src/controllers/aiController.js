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

  } catch (error) {

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

  } catch (error) {

    res.status(500).json({
      message:
        "AI Error",
    });

  }

};