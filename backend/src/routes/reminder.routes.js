const express =
require("express");

const router =
express.Router();

const auth =
require("../middleware/auth");

const {
  sendSubscriptionReminders,
} = require(
  "../controllers/reminderController"
);

router.get(
  "/",
  auth,
  sendSubscriptionReminders
);

module.exports =
router;