const knex =
require("../config/db");

const {
  sendReminder,
} = require(
  "../services/email.service"
);

exports.sendSubscriptionReminders =
async (req, res) => {

  try {

    const subscriptions =
      await knex(
        "subscriptions"
      )
      .where({

        user_id:
          req.user.id,

      });

    const user =
      await knex(
        "users"
      )
      .where({

        id:
          req.user.id,

      })
      .first();

    for (
      const subscription
      of subscriptions
    ) {

      await sendReminder(

        user.email,

        subscription

      );

    }

    res.json({

      success: true,

      message:
        "Reminder emails sent",

    });

  }

  catch (error) {

    res.status(500).json({

      error:
        error.message,

    });

  }

};