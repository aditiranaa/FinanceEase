import {
  CalendarDays,
  ChevronDown,
  Download,
  FileBarChart2,
} from "lucide-react";

export default function AnalyticsHeader() {
  return (
    <div className="flex items-start justify-between">

      {/* Left */}
      <div className="max-w-md">
        <h1 className="text-[30px] font-bold leading-tight tracking-tight text-gray-900 dark:text-white">
          Reports & Analytics
        </h1>

        <p className="mt-2 text-base text-gray-500 dark:text-gray-400">
          Gain insights into your financial performance.
        </p>
      </div>

      {/* Right */}
      <div className="flex items-center gap-4 shrink-0">
        <button
          className="
            flex
            h-10
            w-40
            items-center
            justify-between
            rounded-xl
            border
            border-gray-200
            dark:border-gray-700
            bg-white
            dark:bg-gray-900
            px-3
            text-sm
            font-medium
            shadow-sm
          "
        >
          <span className="flex items-center gap-3">
            <CalendarDays size={18} />
            This Month
          </span>

          <ChevronDown size={16} />
        </button>

        <button
          className="
            flex
            h-10
            w-40
            items-center
            justify-between
            rounded-xl
            border
            border-gray-200
            dark:border-gray-700
            bg-white
            dark:bg-gray-900
            px-5
            text-sm
            font-medium
            shadow-sm
          "
        >
          <span className="flex items-center gap-3">
            <FileBarChart2 size={18} />
            All Reports
          </span>

          <ChevronDown size={16} />
        </button>

        <button
          className="
            flex
            h-10
            w-40
            items-center
            justify-center
            gap-2
            rounded-xl
            bg-blue-600
            text-white
            font-semibold
            shadow-sm
            hover:bg-blue-700
          "
        >
          <Download size={18} />
          Export
        </button>

      </div>

    </div>
  );
}