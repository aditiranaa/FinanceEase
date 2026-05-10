const { v4: uuidv4 } = require('uuid');
const knex = require('../config/db');

async function recomputeMetrics(userId) {
  try {
    const now = new Date();

    // totals
    const [txSumRow] = await knex('transactions')
      .where({ user_id: userId })
      .sum({ total: 'amount' })
      .limit(1);

    const [earnSumRow] = await knex('earnings')
      .where({ user_id: userId })
      .sum({ total: 'amount' })
      .limit(1);

    const totalExpenses = Number(txSumRow?.total || 0);
    const totalIncome = Number(earnSumRow?.total || 0);

    // month-to-date
    const monthStart = new Date(
      now.getFullYear(),
      now.getMonth(),
      1
    );

    const monthStartISO =
      monthStart.toISOString().slice(0, 10);

    const [mtdRow] = await knex('transactions')
      .where({ user_id: userId })
      .andWhere('date', '>=', monthStartISO)
      .sum({ monthlyExpenses: 'amount' })
      .limit(1);

    const monthlyExpenses =
      Number(mtdRow?.monthlyExpenses || 0);

    // daily burn
    const daysPassed = now.getDate() || 1;

    const dailyBurn =
      monthlyExpenses / daysPassed;

    // upcoming bills
    const horizon = new Date(
      now.getTime() + 30 * 24 * 3600 * 1000
    );

    const horizonISO =
      horizon.toISOString().slice(0, 10);

    const upcomingRows = await knex('subscriptions')
      .where({ user_id: userId })
      .andWhere(
        'next_due',
        '>=',
        now.toISOString().slice(0, 10)
      )
      .andWhere('next_due', '<=', horizonISO);

    const upcomingTotal =
      upcomingRows.reduce(
        (s, r) => s + Number(r.amount || 0),
        0
      );

    // goals
    const goals = await knex('goals')
      .where({ user_id: userId })
      .orderBy('id', 'asc');

    let selectedGoal = null;

    if (goals && goals.length) {
      selectedGoal =
        goals.find(g =>
          (g.name || '')
            .toLowerCase()
            .includes('laptop')
        ) || goals[0];
    }

    const savingsGoal = selectedGoal
      ? {
          name: selectedGoal.name,
          target: Number(selectedGoal.target || 0),
          saved: Number(selectedGoal.saved || 0),
          percent:
            selectedGoal.target
              ? (Number(selectedGoal.saved || 0) /
                  Number(selectedGoal.target)) *
                100
              : 0
        }
      : {
          name: null,
          target: 0,
          saved: 0,
          percent: 0
        };

    const metrics = {
      totalExpenses,
      totalIncome,
      monthlyExpenses,
      dailyBurn,
      upcoming: {
        count: upcomingRows.length,
        total: upcomingTotal
      },
      savingsGoal,
      computed_at: new Date().toISOString()
    };

    // upsert cache
    const existing = await knex('cached_metrics')
      .where({ user_id: userId })
      .first();

    if (existing) {
      await knex('cached_metrics')
        .where({ user_id: userId })
        .update({
          metrics_json: JSON.stringify(metrics),
          updated_at: knex.fn.now()
        });
    } else {
      await knex('cached_metrics').insert({
        id: uuidv4(),
        user_id: userId,
        metrics_json: JSON.stringify(metrics),
        updated_at: knex.fn.now()
      });
    }

    return metrics;

  } catch (err) {
    console.error(
      'recomputeMetrics error',
      err
    );

    throw err;
  }
}

module.exports = {
  recomputeMetrics
};