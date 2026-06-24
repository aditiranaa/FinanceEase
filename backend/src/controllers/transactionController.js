const db =
require("../config/db");

const {
  v4: uuidv4,
} = require("uuid");

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

    const id =
      uuidv4();

    await db(
      "transactions"
    ).insert({

      id,

      user_id:
        req.user.id,

      amount,

      category,

      type,

      description,

      date,

    });

    const transaction =
      await db(
        "transactions"
      )
      .where({
        id,
      })
      .first();

    res.status(201).json(
      transaction
    );

  }

  catch (err) {

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

  }

  catch (err) {

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

    if (!updated) {

      return res.status(404).json({

        error:
          "Transaction not found",

      });

    }

    res.json(
      updated
    );

  }

  catch (err) {

    res.status(500).json({

      error:
        err.message,

    });

  }

};

exports.deleteTransaction =
async (req, res) => {

  try {

    const deleted =
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

    if (!deleted) {

      return res.status(404).json({

        error:
          "Transaction not found",

      });

    }

    res.json({

      success: true,

      message:
        "Transaction deleted successfully",

    });

  }

  catch (err) {

    res.status(500).json({

      error:
        err.message,

    });

  }

};