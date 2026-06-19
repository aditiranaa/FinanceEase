const express =
require("express");

const auth =
require("../middleware/auth");

const router =
express.Router();

const {
  getAIInsight,
  getAIHistory,
} = require(
  "../controllers/aiController"
);

router.get(
  "/history",
  auth,
  getAIHistory
);

router.post(
  "/",
  auth,
  getAIInsight
);

module.exports =
router;