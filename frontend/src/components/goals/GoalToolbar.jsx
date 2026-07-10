import { Search } from "lucide-react";

export default function GoalToolbar({
  search,
  setSearch,
  category,
  setCategory,
  status,
  setStatus,
  sort,
  setSort,
}) {
  return (
    <div className="bg-white rounded-2xl shadow-sm border border-gray-100 p-5">

      <div className="grid gap-4 lg:grid-cols-4">

        {/* Search */}

        <div className="relative">

          <Search
            size={18}
            className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-400"
          />

          <input
            type="text"
            placeholder="Search goals..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="
              w-full
              h-12
              pl-11
              pr-4
              rounded-xl
              border
              border-gray-200
              focus:ring-2
              focus:ring-blue-500
              outline-none
            "
          />

        </div>

        {/* Category */}

        <select
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          className="h-12 rounded-xl border border-gray-200 px-4"
        >
          <option value="all">All Categories</option>
          <option value="General">General</option>
          <option value="Emergency">Emergency</option>
          <option value="Vacation">Vacation</option>
          <option value="Home">Home</option>
          <option value="Vehicle">Vehicle</option>
          <option value="Education">Education</option>
        </select>

        {/* Status */}

        <select
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          className="h-12 rounded-xl border border-gray-200 px-4"
        >
          <option value="all">All Status</option>
          <option value="active">Active</option>
          <option value="completed">Completed</option>
        </select>

        {/* Sort */}

        <select
          value={sort}
          onChange={(e) => setSort(e.target.value)}
          className="h-12 rounded-xl border border-gray-200 px-4"
        >
          <option value="deadline">Deadline</option>
          <option value="progress">Progress</option>
          <option value="saved">Saved Amount</option>
          <option value="target">Target Amount</option>
        </select>

      </div>

    </div>
  );
}