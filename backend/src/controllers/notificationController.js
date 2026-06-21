const knex =
require("../config/db");

exports.getNotifications =
async (req, res) => {

  try {

    const notifications = [];

    // BUDGET ALERTS
    const budgets =
      await knex("budgets")
      .where({
        user_id:
          req.user.id,
      });

    for (const budget of budgets) {

      const limit =
        Number(
          budget.amount ||
          budget.limit ||
          0
        );

      const spent =
        Number(
          budget.spent || 0
        );

      if (
        limit > 0 &&
        spent >= limit
      ) {

        notifications.push({

          type:
            "danger",

          message:
            `${budget.category} budget exceeded.`

        });

      }

      else if (
        limit > 0 &&
        spent >=
        limit * 0.8
      ) {

        notifications.push({

          type:
            "warning",

          message:
            `${budget.category} budget is above 80%.`

        });

      }

    }

    // SUBSCRIPTIONS
    const subscriptions =
      await knex(
        "subscriptions"
      )
      .where({
        user_id:
          req.user.id,
      });

    const today =
      new Date();

    for (
      const sub
      of subscriptions
    ) {

      if (
        !sub.next_due
      ) continue;

      const due =
        new Date(
          sub.next_due
        );

      const diff =
        Math.ceil(
          (
            due - today
          ) /
          (
            1000 *
            60 *
            60 *
            24
          )
        );

      if (
        diff >= 0 &&
        diff <= 7
      ) {

        notifications.push({

          type:
            "info",

          message:
            `${sub.name} subscription is due in ${diff} day(s).`

        });

      }

    }

    // GOALS
    const goals =
      await knex(
        "goals"
      )
      .where({
        user_id:
          req.user.id,
      });

    for (
      const goal
      of goals
    ) {

      if (
        Number(
          goal.current_amount
        ) >=
        Number(
          goal.target_amount
        )
      ) {

        notifications.push({

          type:
            "success",

          message:
            `${goal.title} goal achieved 🎉`

        });

      }

    }

    res.json(
      notifications
    );

  }

  catch (error) {

    res.status(500).json({

      error:
        error.message,

    });

  }

};

