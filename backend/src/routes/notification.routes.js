const express = require("express");
const router = express.Router();

const auth = require("../middleware/auth");

const {
  getNotifications,
  markAsRead,
  deleteNotification,
} = require("../controllers/notificationController");

router.use(auth);

router.get("/", getNotifications);

router.put(
  "/:id/read",
  markAsRead
);

router.delete(
  "/:id",
  deleteNotification
);

module.exports = router;