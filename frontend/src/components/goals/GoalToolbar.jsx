import {
  Search,
  Filter,
  ArrowUpDown,
  Plus,
  X,
} from "lucide-react";

const CATEGORIES = [
  "General",
  "Emergency",
  "Vacation",
  "Home",
  "Education",
  "Vehicle",
  "Retirement",
];

const STATUS_OPTIONS = [
  { value: "all", label: "All Status" },
  { value: "active", label: "Active" },
  { value: "completed", label: "Completed" },
];

const SORT_OPTIONS = [
  { value: "deadline", label: "Deadline" },
  { value: "saved", label: "Saved Amount" },
  { value: "target", label: "Target Amount" },
  { value: "progress", label: "Progress" },
];

export default function GoalToolbar({
  search,
  setSearch,
  category,
  setCategory,
  status,
  setStatus,
  sort,
  setSort,
  onAdd,
}) {
  const hasFilters =
    search ||
    category !== "all" ||
    status !== "all" ||
    sort !== "deadline";

  const clearFilters = () => {
    setSearch("");
    setCategory("all");
    setStatus("all");
    setSort("deadline");
  };

  return (
    <div
      className="
        rounded-2xl
        border
        border-gray-200
        dark:border-gray-700
        bg-white
        dark:bg-gray-900
        p-4
        shadow-sm
      "
    >
      <div className="flex flex-col gap-5 xl:flex-row xl:items-center">
        <div className="relative flex-1">
          <Search
            size={18}
            className="
              absolute
              left-4
              top-1/2
              -translate-y-1/2
              text-gray-400
            "
          />

          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search goals..."
            className="
              w-full
              rounded-xl
              border
              border-gray-200
              dark:border-gray-700
              bg-gray-50
              dark:bg-gray-800
              py-3
              pl-11
              pr-11
              outline-none
              transition
              focus:ring-2
              focus:ring-blue-500
            "
          />

          {search && (
            <button
              type="button"
              onClick={() => setSearch("")}
              className="
                absolute
                right-3
                top-1/2
                -translate-y-1/2
                rounded-full
                p-1
                text-gray-400
                hover:bg-gray-200
                dark:hover:bg-gray-700
              "
            >
              <X size={15} />
            </button>
          )}
        </div>

        <div className="flex flex-wrap gap-3">
          <div className="relative">
            <Filter
              size={16}
              className="
                absolute
                left-3
                top-1/2
                -translate-y-1/2
                text-gray-400
              "
            />

            <select
              value={category}
              onChange={(e) => setCategory(e.target.value)}
              className="
                appearance-none
                rounded-xl
                border
                border-gray-200
                dark:border-gray-700
                bg-white
                dark:bg-gray-800
                py-3
                pl-10
                pr-8
              "
            >
              <option value="all">All Categories</option>

              {CATEGORIES.map((category) => (
                <option
                  key={category}
                  value={category}
                >
                  {category}
                </option>
              ))}
            </select>
          </div>

          <select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            className="
              rounded-xl
              border
              border-gray-200
              dark:border-gray-700
              bg-white
              dark:bg-gray-800
              px-4
              py-3
            "
          >
            {STATUS_OPTIONS.map((option) => (
              <option
                key={option.value}
                value={option.value}
              >
                {option.label}
              </option>
            ))}
          </select>

          <div className="relative">
            <ArrowUpDown
              size={16}
              className="
                absolute
                left-3
                top-1/2
                -translate-y-1/2
                text-gray-400
              "
            />

            <select
              value={sort}
              onChange={(e) => setSort(e.target.value)}
              className="
                appearance-none
                rounded-xl
                border
                border-gray-200
                dark:border-gray-700
                bg-white
                dark:bg-gray-800
                py-3
                pl-10
                pr-8
              "
            >
              {SORT_OPTIONS.map((option) => (
                <option
                  key={option.value}
                  value={option.value}
                >
                  {option.label}
                </option>
              ))}
            </select>
          </div>

          {hasFilters && (
            <button
              type="button"
              onClick={clearFilters}
              className="
                rounded-xl
                border
                border-gray-200
                dark:border-gray-700
                px-4
                py-3
                text-xs
                transition
                hover:bg-gray-100
                dark:hover:bg-gray-800
              "
            >
              Clear
            </button>
          )}

          {onAdd && (
            <button
              type="button"
              onClick={onAdd}
              className="
                inline-flex
                items-center
                gap-2
                rounded-xl
                bg-blue-600
                px-5
                py-3
                font-medium
                text-white
                transition-colors
                hover:bg-blue-700
              "
            >
              <Plus size={18} />
              New Goal
            </button>
          )}
        </div>
      </div>
    </div>
  );
}