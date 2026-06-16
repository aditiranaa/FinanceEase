const BudgetAlerts = ({
  budgets,
  transactions,
}) => {

  const alerts = [];

  budgets.forEach(
    (budget) => {

      const spent =
        transactions
          .filter(
            (transaction) =>
              transaction.category ===
              budget.category
          )
          .reduce(
            (total, transaction) =>
              total +
              Math.abs(
                Number(
                  transaction.amount
                )
              ),
            0
          );

      const percentage =
        Number(
          budget.amount
        ) > 0
          ? (
              spent /
              Number(
                budget.amount
              )
            ) * 100
          : 0;

      if (percentage >= 100) {

        alerts.push(
          `⚠️ ${budget.category} budget exceeded`
        );

      } else if (
        percentage >= 90
      ) {

        alerts.push(
          `⚠️ ${budget.category} budget at ${Math.round(
            percentage
          )}%`
        );

      }

    }
  );

  return (

    <div
      className="
        bg-white
        p-6
        rounded-2xl
        shadow-sm
        mt-8
      "
    >

      <h2
        className="
          text-2xl
          font-bold
          mb-4
        "
      >
        Budget Alerts
      </h2>

      {alerts.length === 0 ? (

        <p
          className="
            text-green-600
          "
        >
          No alerts 🎉
        </p>

      ) : (

        alerts.map(
          (alert, index) => (

            <div
              key={index}
              className="
                bg-red-50
                text-red-600
                p-3
                rounded-lg
                mb-3
              "
            >

              {alert}

            </div>

          )
        )

      )}

    </div>

  );

};

export default BudgetAlerts;