const knex = require('./db');

async function ensureSchema() {

  // USERS
  if (!(await knex.schema.hasTable('users'))) {
    await knex.schema.createTable('users', t => {
      t.string('id').primary();

      t.string('email')
        .notNullable()
        .unique();

      t.string('password_hash')
        .notNullable();

      t.string('name');

      t.timestamp('created_at')
        .defaultTo(knex.fn.now());
    });
  }

  // TRANSACTIONS
  if (!(await knex.schema.hasTable('transactions'))) {
    await knex.schema.createTable('transactions', t => {
      t.string('id').primary();

      t.string('user_id')
        .references('id')
        .inTable('users')
        .onDelete('CASCADE');

      t.decimal('amount', 12, 2)
        .notNullable();

      t.date('date')
        .notNullable();

      t.string('description')
        .notNullable();

      t.string('category')
        .notNullable();

      t.timestamp('created_at')
        .defaultTo(knex.fn.now());

      t.timestamp('updated_at');
    });
  }

  // BUDGETS
  if (!(await knex.schema.hasTable('budgets'))) {
    await knex.schema.createTable('budgets', t => {
      t.string('id').primary();

      t.string('user_id')
        .references('id')
        .inTable('users')
        .onDelete('CASCADE');

      t.string('category')
        .notNullable();

      t.decimal('limit', 12, 2)
        .defaultTo(0);

      t.decimal('spent', 12, 2)
        .defaultTo(0);

      t.timestamp('created_at')
        .defaultTo(knex.fn.now());
    });
  }

  // GOALS
  if (!(await knex.schema.hasTable('goals'))) {
    await knex.schema.createTable('goals', t => {
      t.string('id').primary();

      t.string('user_id')
        .references('id')
        .inTable('users')
        .onDelete('CASCADE');

      t.string('name')
        .notNullable();

      t.decimal('target', 12, 2)
        .defaultTo(0);

      t.decimal('saved', 12, 2)
        .defaultTo(0);

      t.date('due_date');

      t.timestamp('created_at')
        .defaultTo(knex.fn.now());
    });
  }

  // SUBSCRIPTIONS
  if (!(await knex.schema.hasTable('subscriptions'))) {
    await knex.schema.createTable('subscriptions', t => {
      t.string('id').primary();

      t.string('user_id')
        .references('id')
        .inTable('users')
        .onDelete('CASCADE');

      t.string('name')
        .notNullable();

      t.string('category')
        .defaultTo('Other');

      t.decimal('amount', 12, 2)
        .defaultTo(0);

      t.string('frequency')
        .defaultTo('Monthly');

      t.date('next_due');

      t.timestamp('created_at')
        .defaultTo(knex.fn.now());
    });
  }

  // EARNINGS
  if (!(await knex.schema.hasTable('earnings'))) {
    await knex.schema.createTable('earnings', t => {
      t.string('id').primary();

      t.string('user_id')
        .references('id')
        .inTable('users')
        .onDelete('CASCADE');

      t.string('source')
        .notNullable();

      t.decimal('amount', 12, 2)
        .defaultTo(0);

      t.timestamp('created_at')
        .defaultTo(knex.fn.now());
    });
  }

  console.log('✅ Database schema ready');
}

module.exports = ensureSchema;