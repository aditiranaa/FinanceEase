const db = require("../config/db");
const { v4: uuid } = require("uuid");

exports.getGoals = async (req, res) => {
  try {
    const goals = await db("goals")
      .where({ user_id: req.user.id })
      .orderBy("created_at", "desc");

    res.json(goals);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

exports.getGoal = async (req, res) => {
  try {
    const goal = await db("goals")
      .where({
        id: req.params.id,
        user_id: req.user.id,
      })
      .first();

    if (!goal) {
      return res.status(404).json({
        message: "Goal not found",
      });
    }

    res.json(goal);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

exports.createGoal = async (req, res) => {
  try {
    const {
      title,
      category,
      target_amount,
      current_amount,
      deadline,
    } = req.body;

    const goal = {
      id: uuid(),
      user_id: req.user.id,
      title,
      category: category || "General",
      target_amount,
      current_amount: current_amount || 0,
      deadline,
      completed:
        Number(current_amount || 0) >=
        Number(target_amount),
    };

    await db("goals").insert(goal);

    res.status(201).json(goal);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

exports.updateGoal = async (req, res) => {
  try {
    const {
      title,
      category,
      target_amount,
      current_amount,
      deadline,
      completed,
    } = req.body;

    const autoCompleted =
      Number(current_amount || 0) >=
      Number(target_amount);

    await db("goals")
      .where({
        id: req.params.id,
        user_id: req.user.id,
      })
      .update({
        title,
        category,
        target_amount,
        current_amount,
        deadline,
        completed:
          completed ?? autoCompleted,
      });

    const updated = await db("goals")
      .where({
        id: req.params.id,
      })
      .first();

    res.json(updated);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

exports.deleteGoal = async (req, res) => {
  try {
    await db("goals")
      .where({
        id: req.params.id,
        user_id: req.user.id,
      })
      .del();

    res.json({
      message: "Goal deleted",
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

exports.completeGoal = async (req, res) => {
  try {
    await db("goals")
      .where({
        id: req.params.id,
        user_id: req.user.id,
      })
      .update({
        completed: true,
      });

    const goal = await db("goals")
      .where({
        id: req.params.id,
      })
      .first();

    res.json(goal);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

exports.getSummary = async (req, res) => {
  try {
    const goals = await db("goals")
      .where({
        user_id: req.user.id,
      });

    const totalGoals = goals.length;

    const completedGoals =
      goals.filter(g => g.completed).length;

    const activeGoals =
      totalGoals - completedGoals;

    const totalTarget =
      goals.reduce(
        (sum, g) =>
          sum + Number(g.target_amount),
        0
      );

    const totalSaved =
      goals.reduce(
        (sum, g) =>
          sum + Number(g.current_amount),
        0
      );

    res.json({
      totalGoals,
      activeGoals,
      completedGoals,
      totalTarget,
      totalSaved,
      completionRate:
        totalTarget === 0
          ? 0
          : Math.round(
              (totalSaved / totalTarget) *
                100
            ),
    });
  } catch (err) {
    res.status(500).json({
      message: err.message,
    });
  }
};