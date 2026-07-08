import { useState } from "react";

export default function NotificationFilters({
  onFilter,
}) {
  const [active, setActive] =
    useState("all");

  const filters = [
    {
      key: "all",
      label: "All",
    },
    {
      key: "unread",
      label: "Unread",
    },
    {
      key: "read",
      label: "Read",
    },
  ];

  const handleFilter = (key) => {
    setActive(key);

    if (onFilter) {
      onFilter(key);
    }
  };

  return (
    <div className="flex gap-3">

      {filters.map((filter) => (
        <button
          key={filter.key}
          onClick={() =>
            handleFilter(filter.key)
          }
          className={`px-4 py-2 rounded-lg transition ${
            active === filter.key
              ? "bg-blue-600 text-white"
              : "bg-gray-100 hover:bg-gray-200"
          }`}
        >
          {filter.label}
        </button>
      ))}

    </div>
  );
}