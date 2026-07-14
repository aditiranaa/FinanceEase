import {
  CreditCard,
  Wallet,
  Clock,
} from "lucide-react";

const formatCurrency = (value) =>
  Number(value || 0).toLocaleString("en-IN", {
    style: "currency",
    currency: "INR",
    maximumFractionDigits: 0,
  });

const Card = ({ title, value, icon, color }) => (
  <div className="bg-white dark:bg-gray-900 rounded-xl shadow-md border border-gray-200 dark:border-gray-800 p-5">
    <div className="flex items-center justify-between">
      <div>
        <p className="text-xs text-gray-500">{title}</p>
        <h2 className="mt-2 text-lg font-bold">{value}</h2>
      </div>

      <div
        className={`w-12 h-12 rounded-full flex items-center justify-center ${color}`}
      >
        {icon}
      </div>
    </div>
  </div>
);

export default function SubscriptionOverview({
  subscriptions = [],
}) {
  const active = subscriptions.filter(
    (s) => s.active
  );

  const monthlyTotal = active.reduce(
    (sum, s) => sum + Number(s.amount),
    0
  );

  const upcoming = active.filter((s) => {
    if (!s.next_due) return false;

    const today = new Date();
    const due = new Date(s.next_due);

    const diff =
      (due - today) /
      (1000 * 60 * 60 * 24);

    return diff >= 0 && diff <= 7;
  });

  return (
    <div className="grid gap-5 md:grid-cols-3">

      <Card
        title="Active Plans"
        value={active.length}
        color="bg-blue-100 text-blue-600"
        icon={<CreditCard />}
      />

      <Card
        title="Monthly Cost"
        value={formatCurrency(monthlyTotal)}
        color="bg-green-100 text-green-600"
        icon={<Wallet />}
      />

      <Card
        title="Renewing Soon"
        value={upcoming.length}
        color="bg-yellow-100 text-yellow-600"
        icon={<Clock />}
      />

    </div>
  );
}