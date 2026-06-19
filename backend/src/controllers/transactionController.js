const db =
require("../config/db");

exports.addTransaction =
async (req, res) => {

  try {

    const {
      amount,
      category,
      type,
      description,
      date,
    } = req.body;

    await db(
      "transactions"
    ).insert({

      user_id:
        req.user.id,

      amount,

      category,

      type,

      description,

      date,

    });

    res.status(201).json({
      success: true,
      message:
        "Transaction added",
    });

  } catch (err) {

    res.status(500).json({
      success: false,
      error:
        err.message,
    });

  }

};

exports.getTransactions =
async (req, res) => {

  try {

    const transactions =
      await db(
        "transactions"
      )

      .where({
        user_id:
          req.user.id,
      })

      .orderBy(
        "date",
        "desc"
      );

    res.json(
      transactions
    );

  } catch (err) {

    res.status(500).json({
      error:
        err.message,
    });

  }

};

exports.updateTransaction =
async (req, res) => {

  try {

    const {
      amount,
      category,
      type,
      description,
      date,
    } = req.body;

    await db(
      "transactions"
    )
      .where({

        id:
          req.params.id,

        user_id:
          req.user.id,

      })
      .update({

        amount,

        category,

        type,

        description,

        date,

      });

    const updated =
      await db(
        "transactions"
      )
        .where({

          id:
            req.params.id,

          user_id:
            req.user.id,

        })
        .first();

    res.json(updated);

  } catch (err) {

    res.status(500).json({
      error:
        err.message,
    });

  }

};

exports.deleteTransaction =
async (req, res) => {

  try {

    await db(
      "transactions"
    )

    .where({

      id:
        req.params.id,

      user_id:
        req.user.id,

    })

    .del();

    res.json({
      success: true,
    });

  } catch (err) {

    res.status(500).json({
      error:
        err.message,
    });

  }

};

