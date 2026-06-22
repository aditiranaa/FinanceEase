const knex =
require("../config/db");

exports.getAnalytics =
async (req, res) => {

  try {

    const transactions =
      await knex(
        "transactions"
      )
      .where({
        user_id:
          req.user.id,
      });

    let income = 0;
    let expenses = 0;

    const categories = {};

    transactions.forEach(
      transaction => {

        const amount =
          Number(
            transaction.amount
          );

        if (
          amount > 0
        ) {

          income += amount;

        }

        else {

          expenses +=
            Math.abs(amount);

        }

        categories[
          transaction.category
        ] =
          (
            categories[
              transaction.category
            ] || 0
          ) +
          Math.abs(
            amount
          );

      }
    );

    const balance =
      income - expenses;

    let topCategory =
      "";

    let max = 0;

    for (
      const category
      in categories
    ) {

      if (
        categories[
          category
        ] > max
      ) {

        max =
          categories[
            category
          ];

        topCategory =
          category;

      }

    }

    res.json({

      income,

      expenses,

      balance,

      topCategory,

    });

  }

  catch (error) {

    res.status(500).json({

      error:
        error.message,

    });

  }

};