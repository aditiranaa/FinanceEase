const express =
require("express");

const router =
express.Router();

const {
  getAIInsight,
} = require(
  "../controllers/aiController"
);

router.post(
  "/",
  getAIInsight
);

module.exports =
router;