import {
  ShoppingCart,
  Popcorn,
  Zap,
  Car,
  Wallet,
  Calendar,
  Pencil,
  Trash2,
} from "lucide-react";
import BudgetProgress from "./BudgetProgress";
import formatCurrency from "../../utils/formatCurrency";

const CATEGORY_STYLE = {
  groceries: {
    icon: "ShoppingCart",
    color: "green",
    description: "Food and household essentials",
  },
  entertainment: {
    icon: "Popcorn",
    color: "amber",
    description: "Movies, streaming, and outings",
  },
  utilities: {
    icon: "Zap",
    color: "blue",
    description: "Electricity, water, internet & bills",
  },
  transportation: {
    icon: "Car",
    color: "red",
    description: "Fuel and travel expenses",
  },
};

const ICONS = {
  ShoppingCart,
  Popcorn,
  Zap,
  Car,
  Wallet,
};

const ICON_BG = {
  green: "bg-emerald-100 text-emerald-600",
  amber: "bg-amber-100 text-amber-500",
  blue: "bg-blue-100 text-blue-600",
  red: "bg-red-100 text-red-500",
  gray: "bg-gray-100 text-gray-500",
};

function getDaysLeftInMonth() {
  const now = new Date();
  const lastDay = new Date(
    now.getFullYear(),
    now.getMonth() + 1,
    0
  ).getDate();

  return lastDay - now.getDate();
}

function getStatus(percentUsed) {
  if (percentUsed >= 100) return "over";
  if (percentUsed >= 80) return "warning";
  return "good";
}

export default function BudgetCard({
  budget,
  onClick,
  onEdit,
  onDelete,
  currency = "INR",
}) {
  const { id, category, limit, spent } = budget;

  const numericLimit = Number(limit || 0);
  const numericSpent = Number(spent || 0);

  const percentUsed =
    numericLimit === 0
      ? 0
      : Math.round((numericSpent / numericLimit) * 100);

  const status = getStatus(percentUsed);

  const style =
    CATEGORY_STYLE[(category || "").toLowerCase()] || {
      icon: "Wallet",
      color: "gray",
      description: "Monthly spending budget",
    };

  const Icon = ICONS[style.icon] || Wallet;

  const daysLeft = getDaysLeftInMonth();

  const card = (
    <>
      {/* Left */}
      <div className="flex w-[330px] items-center gap-5">
        <div
          className={`flex h-20 w-20 items-center justify-center rounded-full ${ICON_BG[style.color]}`}
        >
          <Icon size={36} />
        </div>

        <div className="min-w-0">
          <h3 className="text-2xl font-bold text-gray-900">
            {category}
          </h3>

          <p className="mt-1 text-base text-gray-500">
            {style.description}
          </p>
        </div>
      </div>

      {/* Center */}
      <div className="flex-1 px-8">
        <BudgetProgress
          percentUsed={percentUsed}
          status={status}
        />

        <div className="mt-4 flex items-center justify-between text-base">
          <span>
            <span className="font-semibold text-red-500">
              {formatCurrency(numericSpent, currency)}
            </span>{" "}
            <span className="text-gray-500">spent</span>
          </span>

          <span className="text-gray-500">
            {formatCurrency(numericLimit, currency)} total
          </span>
        </div>
      </div>

      {/* Divider */}
      <div className="mx-6 h-24 w-px bg-gray-200" />

      {/* Right */}
      <div className="w-40 text-center">
        <div className="flex items-center justify-center gap-2">
          <Calendar className="text-emerald-600" size={24} />

          <span className="text-5xl font-bold text-gray-900">
            {daysLeft}
          </span>
        </div>

        <p className="mt-2 text-sm text-gray-500">
          days left in month
        </p>
      </div>

      {(onEdit || onDelete) && (
        <div className="ml-5 flex flex-col gap-2">
          {onEdit && (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                onEdit(budget);
              }}
              className="rounded-lg p-2 text-gray-400 transition hover:bg-emerald-50 hover:text-emerald-600"
            >
              <Pencil size={18} />
            </button>
          )}

          {onDelete && (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                onDelete(id);
              }}
              className="rounded-lg p-2 text-gray-400 transition hover:bg-red-50 hover:text-red-600"
            >
              <Trash2 size={18} />
            </button>
          )}
        </div>
      )}
    </>
  );

  const classes =
    "w-full rounded-2xl border border-gray-100 bg-white px-8 py-7 shadow-sm transition-all hover:shadow-md flex items-center";

  if (onClick) {
    return (
      <button
        type="button"
        onClick={onClick}
        className={classes}
      >
        {card}
      </button>
    );
  }

  return <div className={classes}>{card}</div>;
}