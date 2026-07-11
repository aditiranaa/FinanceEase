import {
  Search,
  Filter,
  ArrowUpDown,
} from "lucide-react";

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
    <div className="
      bg-white
      dark:bg-gray-900
      rounded-3xl
      border
      border-gray-200
      dark:border-gray-700
      shadow-sm
      p-6
    ">

      <div className="flex flex-col lg:flex-row gap-5">

        {/* Search */}

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
            onChange={(e) =>
              setSearch(e.target.value)
            }
            placeholder="Search goals..."
            className="
              w-full
              pl-11
              pr-4
              py-3
              rounded-xl
              border
              border-gray-200
              dark:border-gray-700
              bg-gray-50
              dark:bg-gray-800
              outline-none
              focus:ring-2
              focus:ring-blue-500
            "
          />

        </div>

        {/* Filters */}

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
              onChange={(e) =>
                setCategory(e.target.value)
              }
              className="
                appearance-none
                pl-10
                pr-8
                py-3
                rounded-xl
                border
                border-gray-200
                bg-white
                dark:bg-gray-800
                dark:border-gray-700
                outline-none
              "
            >
              <option value="all">
                All Categories
              </option>

              <option value="General">
                General
              </option>

              <option value="Emergency">
                Emergency
              </option>

              <option value="Vacation">
                Vacation
              </option>

              <option value="Home">
                Home
              </option>

              <option value="Education">
                Education
              </option>

              <option value="Vehicle">
                Vehicle
              </option>

              <option value="Retirement">
                Retirement
              </option>

            </select>

          </div>

          <select
            value={status}
            onChange={(e) =>
              setStatus(e.target.value)
            }
            className="
              rounded-xl
              border
              border-gray-200
              bg-white
              dark:bg-gray-800
              dark:border-gray-700
              px-4
              py-3
            "
          >
            <option value="all">
              All Status
            </option>

            <option value="active">
              Active
            </option>

            <option value="completed">
              Completed
            </option>

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
              onChange={(e) =>
                setSort(e.target.value)
              }
              className="
                appearance-none
                pl-10
                pr-8
                py-3
                rounded-xl
                border
                border-gray-200
                bg-white
                dark:bg-gray-800
                dark:border-gray-700
              "
            >
              <option value="deadline">
                Deadline
              </option>

              <option value="saved">
                Saved Amount
              </option>

              <option value="target">
                Target Amount
              </option>

              <option value="progress">
                Progress
              </option>

            </select>

          </div>

        </div>

      </div>

    </div>
  );
}