const express = require('express');

const { v4: uuidv4 } = require('uuid');

const knex = require('../config/db');

const requireAuth = require('../middleware/auth');

const {
  recomputeMetrics
} = require('../services/metrics.service');

function makeRouterFor(
  tableName,
  requiredFields = []
) {
  const router = express.Router();

  // GET ALL
  router.get(
    '/',
    requireAuth,
    async (req, res) => {
      try {
        const items = await knex(tableName)
          .where({ user_id: req.user.id })
          .orderBy('created_at', 'desc');

        res.json(items);

      } catch (err) {
        console.error('GET error', err);

        res.status(500).json({
          error: 'server error'
        });
      }
    }
  );

  // CREATE
  router.post(
    '/',
    requireAuth,
    async (req, res) => {
      try {
        const data = req.body || {};

        for (const field of requiredFields) {
          if (data[field] === undefined) {
            return res.status(400).json({
              error: `${field} required`
            });
          }
        }

        const id = data.id || uuidv4();

        const row = {
          ...data,
          id,
          user_id: req.user.id
        };

        await knex(tableName).insert(row);

        const inserted = await knex(tableName)
          .where({ id })
          .first();

        try {
          await recomputeMetrics(req.user.id);
        } catch (e) {
          console.error(
            'recompute failed',
            e
          );
        }

        res.status(201).json(inserted);

      } catch (err) {
        console.error('POST error', err);

        res.status(500).json({
          error: 'server error'
        });
      }
    }
  );

  // GET ONE
  router.get(
    '/:id',
    requireAuth,
    async (req, res) => {
      try {
        const row = await knex(tableName)
          .where({
            id: req.params.id,
            user_id: req.user.id
          })
          .first();

        if (!row) {
          return res.status(404).json({
            error: 'not found'
          });
        }

        res.json(row);

      } catch (err) {
        console.error('GET ONE error', err);

        res.status(500).json({
          error: 'server error'
        });
      }
    }
  );

  // UPDATE
  router.put(
    '/:id',
    requireAuth,
    async (req, res) => {
      try {
        const updated = {
          ...req.body,
          updated_at: knex.fn.now()
        };

        await knex(tableName)
          .where({
            id: req.params.id,
            user_id: req.user.id
          })
          .update(updated);

        const row = await knex(tableName)
          .where({
            id: req.params.id,
            user_id: req.user.id
          })
          .first();

        if (!row) {
          return res.status(404).json({
            error: 'not found'
          });
        }

        try {
          await recomputeMetrics(req.user.id);
        } catch (e) {
          console.error(
            'recompute failed',
            e
          );
        }

        res.json(row);

      } catch (err) {
        console.error('PUT error', err);

        res.status(500).json({
          error: 'server error'
        });
      }
    }
  );

  // DELETE
  router.delete(
    '/:id',
    requireAuth,
    async (req, res) => {
      try {
        const row = await knex(tableName)
          .where({
            id: req.params.id,
            user_id: req.user.id
          })
          .first();

        if (!row) {
          return res.status(404).json({
            error: 'not found'
          });
        }

        await knex(tableName)
          .where({
            id: req.params.id,
            user_id: req.user.id
          })
          .del();

        try {
          await recomputeMetrics(req.user.id);
        } catch (e) {
          console.error(
            'recompute failed',
            e
          );
        }

        res.json({
          removed: row
        });

      } catch (err) {
        console.error('DELETE error', err);

        res.status(500).json({
          error: 'server error'
        });
      }
    }
  );

  return router;
}

module.exports = makeRouterFor;