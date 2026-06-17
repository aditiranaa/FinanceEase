const { GoogleGenAI } =
require("@google/genai");

const ai =
new GoogleGenAI({
  apiKey:
    process.env.GEMINI_API_KEY,
});

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