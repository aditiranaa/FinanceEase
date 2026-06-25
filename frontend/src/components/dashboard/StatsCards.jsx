import {
  Wallet,
  TrendingUp,
  TrendingDown,
  PiggyBank,
} from "lucide-react";

const StatsCards = ({
  balance,
  income,
  expenses,
  savings,
}) => {

  const cards = [

    {
      title: "Total Balance",
      amount: `₹${Number(balance).toLocaleString("en-IN")}`,
      icon: <Wallet size={28} />,
      bg: "bg-blue-500",
    },

    {
      title: "Income",
      amount: `₹${Number(income).toLocaleString("en-IN")}`,
      icon: <TrendingUp size={28} />,
      bg: "bg-green-500",
    },

    {
      title: "Expenses",
      amount: `₹${Math.abs(expenses).toLocaleString("en-IN")}`,
      icon: <TrendingDown size={28} />,
      bg: "bg-red-500",
    },

    {
      title: "Savings",
      amount: `₹${Number(savings).toLocaleString("en-IN")}`,
      icon: <PiggyBank size={28} />,
      bg: "bg-purple-500",
    },

  ];

  return (

    <div
      className="
        grid
        grid-cols-1
        md:grid-cols-2
        xl:grid-cols-4
        gap-6
        mt-8
      "
    >

      {cards.map((card) => (

        <div
          key={card.title}

          className="
            bg-white
            dark:bg-gray-900
            rounded-2xl
            p-6
            shadow-sm
            hover:shadow-xl
            hover:-translate-y-1
            transition-all
            duration-300
            "
        >

          <div
            className="
              flex
              justify-between
              items-center
            "
          >

            <div>

              <p
                className="
                text-gray-500
                dark:text-gray-300
                "
                >
                {card.title}
              </p>

              <h2
                className="
                  text-3xl
                  font-bold
                  mt-2
                  text-gray-800
                  dark:text-white
                "
              >
                {card.amount}
              </h2>

            </div>

            <div
              className={`
                ${card.bg}
                text-white
                p-4
                rounded-xl
              `}
            >
              {card.icon}
            </div>

          </div>

        </div>

      ))}

    </div>
  );
};

export default StatsCards;