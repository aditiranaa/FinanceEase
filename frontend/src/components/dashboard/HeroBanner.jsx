import {
  ArrowUpRight,
} from "lucide-react";

const HeroBanner = ({
  balance,
}) => {

  return (

    <div
      className="
        mt-4
        rounded-2xl
        bg-gradient-to-r
        from-emerald-500
        via-green-500
        to-teal-500
        text-white
        p-8
        shadow-xl
        flex
        flex-col
        lg:flex-row
        justify-between
        items-center
        gap-4
      "
    >

      <div>

        <h1
          className="
            text-4xl
            font-bold
          "
        >
          👋 Welcome Back
        </h1>

        <p
          className="
            mt-3
            text-green-100
            text-lg
            max-w-xl
          "
        >
          Stay on top of your finances,
          monitor your spending,
          and achieve your savings goals
          effortlessly.
        </p>

      </div>

      <div
        className="
          bg-white/20
          backdrop-blur-md
          rounded-2xl
          px-8
          py-4
          text-center
          min-w-[260px]
        "
      >

        <p className="text-green-100">
          Total Balance
        </p>

        <h2
          className="
            text-4xl
            font-extrabold
            mt-2
          "
        >
          ₹
          {
            Number(balance)
            .toLocaleString("en-IN")
          }
        </h2>

        <div
          className="
            flex
            items-center
            justify-center
            gap-2
            mt-4
            text-green-100
          "
        >

          <ArrowUpRight
            size={18}
          />

          <span>
            Keep growing 🚀
          </span>

        </div>

      </div>

    </div>

  );

};

export default HeroBanner;