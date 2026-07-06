const express = require("express");

const router = express.Router();

const auth = require("../middleware/auth");

const {
  getGoals,
  getGoal,
  createGoal,
  updateGoal,
  deleteGoal,
  completeGoal,
  getSummary,
} = require("../controllers/goalController");

router.use(auth);

router.get("/", getGoals);

router.get("/summary", getSummary);

router.get("/:id", getGoal);

router.post("/", createGoal);

router.put("/:id", updateGoal);

router.put("/:id/complete", completeGoal);

router.delete("/:id", deleteGoal);

module.exports = router;