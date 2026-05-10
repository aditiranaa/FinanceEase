const express = require('express');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');

const knex = require('../config/db');

const router = express.Router();

const JWT_SECRET =
  process.env.JWT_SECRET || 'dev_jwt_secret_change_me';

const BCRYPT_ROUNDS = parseInt(
  process.env.BCRYPT_ROUNDS || '10',
  10
);

function signToken(payload) {
  const jwt = require('jsonwebtoken');

  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: '7d'
  });
}

// REGISTER
router.post('/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: 'email and password required'
      });
    }

    const existing = await knex('users')
      .where({ email })
      .first();

    if (existing) {
      return res.status(409).json({
        error: 'User already exists'
      });
    }

    const hashed = await bcrypt.hash(
      password,
      BCRYPT_ROUNDS
    );

    const id = uuidv4();

    await knex('users').insert({
      id,
      email,
      password_hash: hashed,
      name: name || null
    });

    const token = signToken({
      id,
      email
    });

    res.status(201).json({
      user: {
        id,
        email,
        name: name || null
      },
      token
    });

  } catch (err) {
    console.error('register error', err);

    res.status(500).json({
      error: 'server error'
    });
  }
});

// LOGIN
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: 'email and password required'
      });
    }

    const user = await knex('users')
      .where({ email })
      .first();

    if (!user) {
      return res.status(401).json({
        error: 'invalid credentials'
      });
    }

    const ok = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!ok) {
      return res.status(401).json({
        error: 'invalid credentials'
      });
    }

    const token = signToken({
      id: user.id,
      email: user.email
    });

    res.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name
      },
      token
    });

  } catch (err) {
    console.error('login error', err);

    res.status(500).json({
      error: 'server error'
    });
  }
});

module.exports = router;