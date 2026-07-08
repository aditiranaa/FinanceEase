import {
  Bell,
  MailOpen,
  Mail,
} from "lucide-react";

const Card = ({
  title,
  value,
  icon,
  color,
}) => (
  <div className="bg-white dark:bg-gray-900 rounded-xl shadow p-5">
    <div className="flex justify-between items-center">
      <div>
        <p className="text-gray-500 text-sm">
          {title}
        </p>

        <h2 className="text-2xl font-bold mt-2">
          {value}
        </h2>
      </div>

      <div
        className={`w-12 h-12 rounded-full flex items-center justify-center ${color}`}
      >
        {icon}
      </div>
    </div>
  </div>
);

export default function NotificationOverview({
  notifications,
}) {
  const total = notifications.length;

  const unread =
    notifications.filter(
      (n) => !n.is_read
    ).length;

  const read = total - unread;

  return (
    <div className="grid gap-5 md:grid-cols-3">

      <Card
        title="Total"
        value={total}
        color="bg-blue-100 text-blue-600"
        icon={<Bell />}
      />

      <Card
        title="Unread"
        value={unread}
        color="bg-red-100 text-red-600"
        icon={<Mail />}
      />

      <Card
        title="Read"
        value={read}
        color="bg-green-100 text-green-600"
        icon={<MailOpen />}
      />

    </div>
  );
}