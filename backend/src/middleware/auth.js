const jwt = require('jsonwebtoken');
const knex = require('../config/db');

const JWT_SECRET =
  process.env.JWT_SECRET || 'dev_jwt_secret_change_me';

async function requireAuth(req, res, next) {
  const auth = req.headers.authorization;

  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'Missing token'
    });
  }

  const token = auth.slice(7);

  try {
    const payload = jwt.verify(token, JWT_SECRET);

    const user = await knex('users')
      .where({ id: payload.id })
      .first();

    if (!user) {
      return res.status(401).json({
        error: 'Invalid token (user not found)'
      });
    }

    req.user = {
      id: user.id,
      email: user.email,
      name: user.name
    };

    next();

  } catch (err) {
    return res.status(401).json({
      error: 'Invalid or expired token'
    });
  }
}

module.exports = requireAuth;