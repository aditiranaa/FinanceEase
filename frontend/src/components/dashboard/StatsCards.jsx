import {
  Wallet,
  TrendingUp,
  TrendingDown,
  PiggyBank,
} from "lucide-react";

const StatsCards = () => {

  const cards = [

    {
      title: "Total Balance",
      amount: "$12,000",
      icon: <Wallet size={28} />,
      bg: "bg-blue-500",
    },

    {
      title: "Income",
      amount: "$8,000",
      icon: <TrendingUp size={28} />,
      bg: "bg-green-500",
    },

    {
      title: "Expenses",
      amount: "$3,000",
      icon: <TrendingDown size={28} />,
      bg: "bg-red-500",
    },

    {
      title: "Savings",
      amount: "$9,000",
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
            rounded-2xl
            p-6
            shadow-sm
            hover:shadow-xl
            transition
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

              <p className="text-gray-500">
                {card.title}
              </p>

              <h2
                className="
                  text-3xl
                  font-bold
                  mt-2
                  text-gray-800
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