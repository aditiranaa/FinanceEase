import { useState } from "react";

export default function AnalyticsFilters({
  onChange,
}) {
  const [period, setPeriod] =
    useState("all");

  const handleChange = (value) => {
    setPeriod(value);

    if (onChange) {
      onChange(value);
    }
  };

  return (
    <div className="bg-white dark:bg-gray-900 rounded-xl shadow p-5 flex flex-wrap gap-3">

      {[
        "all",
        "month",
        "quarter",
        "year",
      ].map((item) => (
        <button
          key={item}
          onClick={() =>
            handleChange(item)
          }
          className={`px-4 py-2 rounded-lg capitalize transition ${
            period === item
              ? "bg-blue-600 text-white"
              : "bg-gray-100 hover:bg-gray-200"
          }`}
        >
          {item}
        </button>
      ))}

    </div>
  );
}