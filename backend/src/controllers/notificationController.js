const db = require("../config/db");

// ===============================
// GET ALL NOTIFICATIONS
// ===============================
exports.getNotifications = async (req, res) => {
  try {
    const notifications = await db("notifications")
      .where({
        user_id: req.user.id,
      })
      .orderBy("created_at", "desc");

    res.json(notifications);

  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Failed to fetch notifications",
    });
  }
};

// ===============================
// MARK AS READ
// ===============================
exports.markAsRead = async (req, res) => {
  try {
    const { id } = req.params;

    await db("notifications")
      .where({
        id,
        user_id: req.user.id,
      })
      .update({
        is_read: true,
      });

    res.json({
      message: "Notification marked as read",
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Failed to update notification",
    });
  }
};

// ===============================
// DELETE NOTIFICATION
// ===============================
exports.deleteNotification = async (req, res) => {
  try {
    const { id } = req.params;

    await db("notifications")
      .where({
        id,
        user_id: req.user.id,
      })
      .del();

    res.json({
      message: "Notification deleted",
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Failed to delete notification",
    });
  }
};