const knex = require("./db");

async function ensureSchema() {
  // ==========================
  // USERS
  // ==========================
  if (!(await knex.schema.hasTable("users"))) {
    await knex.schema.createTable("users", (table) => {
      table.string("id").primary();

      table.string("email").notNullable().unique();

      table.string("password_hash").notNullable();

      table.string("name").notNullable();

      table.timestamp("created_at").defaultTo(knex.fn.now());

      table.timestamp("updated_at").nullable();
    });
  }

  // ==========================
  // TRANSACTIONS
  // ==========================
  if (!(await knex.schema.hasTable("transactions"))) {
    await knex.schema.createTable("transactions", (table) => {
      table.string("id").primary();

      table
        .string("user_id")
        .references("id")
        .inTable("users")
        .onDelete("CASCADE");

      table.decimal("amount", 12, 2).notNullable();

      table
        .enu("type", ["income", "expense"])
        .notNullable();

      table.string("category").notNullable();

      table.string("description");

      table.date("date").notNullable();

      table.timestamp("created_at").defaultTo(knex.fn.now());

      table.timestamp("updated_at");
    });
  }

  // ==========================
  // BUDGETS
  // ==========================
  if (!(await knex.schema.hasTable("budgets"))) {
    await knex.schema.createTable("budgets", (table) => {
      table.string("id").primary();

      table
        .string("user_id")
        .references("id")
        .inTable("users")
        .onDelete("CASCADE");

      table.string("category").notNullable();

      table.decimal("limit", 12, 2).defaultTo(0);

      table.decimal("spent", 12, 2).defaultTo(0);

      table
        .string("month")
        .notNullable()
        .defaultTo(knex.raw("to_char(current_date, 'YYYY-MM')"));

      table.timestamp("created_at").defaultTo(knex.fn.now());

      table.timestamp("updated_at");
    });
  }

  // ==========================
  // GOALS
  // ==========================
  if (!(await knex.schema.hasTable("goals"))) {
    await knex.schema.createTable("goals", (table) => {
      table.string("id").primary();

      table
        .string("user_id")
        .references("id")
        .inTable("users")
        .onDelete("CASCADE");

      table.string("title").notNullable();

      table.string("category").defaultTo("General");

      table.decimal("target_amount", 12, 2).defaultTo(0);

      table.decimal("current_amount", 12, 2).defaultTo(0);

      table.date("deadline");

      table.boolean("completed").defaultTo(false);

      table.timestamp("created_at").defaultTo(knex.fn.now());

      table.timestamp("updated_at");
    });
  }

  // ==========================
  // SUBSCRIPTIONS
  // ==========================
  if (!(await knex.schema.hasTable("subscriptions"))) {
    await knex.schema.createTable("subscriptions", (table) => {
      table.string("id").primary();

      table
        .string("user_id")
        .references("id")
        .inTable("users")
        .onDelete("CASCADE");

      table.string("name").notNullable();

      table.string("category").defaultTo("Other");

      table.decimal("amount", 12, 2).defaultTo(0);

      table.string("frequency").defaultTo("Monthly");

      table.date("next_due");

      table.boolean("active").defaultTo(true);

      table.date("cancelled_at");

      table.timestamp("created_at").defaultTo(knex.fn.now());

      table.timestamp("updated_at");
    });
  }

  // ==========================
  // EARNINGS
  // ==========================
  if (!(await knex.schema.hasTable("earnings"))) {
    await knex.schema.createTable("earnings", (table) => {
      table.string("id").primary();

      table
        .string("user_id")
        .references("id")
        .inTable("users")
        .onDelete("CASCADE");

      table.string("source").notNullable();

      table.decimal("amount", 12, 2).defaultTo(0);

      table.date("date").defaultTo(knex.fn.now());

      table.timestamp("created_at").defaultTo(knex.fn.now());

      table.timestamp("updated_at");
    });
  }

  // ==========================
  // NOTIFICATIONS
  // ==========================
  if (!(await knex.schema.hasTable("notifications"))) {
    await knex.schema.createTable("notifications", (table) => {
      table.string("id").primary();

      table
        .string("user_id")
        .references("id")
        .inTable("users")
        .onDelete("CASCADE");

      table.string("title").notNullable();

      table.text("message").notNullable();

      table.string("type").defaultTo("info");
      // info | warning | success | reminder

      table.boolean("is_read").defaultTo(false);

      table.timestamp("created_at").defaultTo(knex.fn.now());
    });
  }

  // ==========================
  // AI HISTORY
  // ==========================
  if (!(await knex.schema.hasTable("ai_history"))) {
    await knex.schema.createTable("ai_history", (table) => {
      table.string("id").primary();

      table
        .string("user_id")
        .references("id")
        .inTable("users")
        .onDelete("CASCADE");

      table.text("prompt").notNullable();

      table.text("response").notNullable();

      table.string("model").defaultTo("gemini-2.5-flash");

      table.timestamp("created_at").defaultTo(knex.fn.now());
    });
  }

  console.log("✅ Database schema ready");
}

module.exports = ensureSchema;