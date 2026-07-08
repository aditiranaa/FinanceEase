const db = require("../config/db");

// ===============================
// GET ALL SUBSCRIPTIONS
// ===============================
exports.getSubscriptions = async (req, res) => {
  try {
    const subscriptions = await db("subscriptions")
      .where({ user_id: req.user.id })
      .orderBy("next_due", "asc");

    res.json(subscriptions);
  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Failed to fetch subscriptions",
    });
  }
};

// ===============================
// CREATE SUBSCRIPTION
// ===============================
exports.createSubscription = async (req, res) => {
  try {
    const { randomUUID } = require("crypto");

    const subscription = {
      id: randomUUID(),
      user_id: req.user.id,
      ...req.body,
    };

    await db("subscriptions").insert(subscription);

    res.status(201).json(subscription);
  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Failed to create subscription",
    });
  }
};

// ===============================
// UPDATE SUBSCRIPTION
// ===============================
exports.updateSubscription = async (req, res) => {
  try {
    const { id } = req.params;

    await db("subscriptions")
      .where({
        id,
        user_id: req.user.id,
      })
      .update(req.body);

    res.json({
      message: "Subscription updated",
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Failed to update subscription",
    });
  }
};

// ===============================
// DELETE SUBSCRIPTION
// ===============================
exports.deleteSubscription = async (req, res) => {
  try {
    await db("subscriptions")
      .where({
        id: req.params.id,
        user_id: req.user.id,
      })
      .del();

    res.json({
      message: "Subscription deleted",
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Failed to delete subscription",
    });
  }
};