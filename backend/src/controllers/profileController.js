const knex =
require("../config/db");

exports.getProfile =
async (req, res) => {

  try {

    const user =
      await knex("users")
        .where({
          id: req.user.id,
        })
        .first();

    if (!user) {

      return res.status(404).json({
        error: "User not found",
      });

    }

    res.json({

      id: user.id,

      name: user.name,

      email: user.email,

      created_at:
        user.created_at,

    });

  }

  catch (error) {

    res.status(500).json({

      error:
        error.message,

    });

  }

};