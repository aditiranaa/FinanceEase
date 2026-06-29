const express =
require("express");

const auth =
require("../middleware/auth");

const router =
express.Router();

const {

  getAIInsight,

  getAIHistory,

  getAISpendingCoach,

} = require(
  "../controllers/aiController"
);

router.get(
  "/history",
  auth,
  getAIHistory
);

router.get(
  "/coach",
  auth,
  getAISpendingCoach
);

router.post(
  "/",
  auth,
  getAIInsight
);

module.exports =
router;