import { Target, Plus } from "lucide-react";

export default function GoalHeader({
  onAdd,
}) {
  return (
    <div className="bg-white rounded-2xl shadow-sm border border-gray-100 p-6">

      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-6">

        <div className="flex items-center gap-4">

          <div className="w-16 h-16 rounded-2xl bg-blue-100 flex items-center justify-center">

            <Target
              size={30}
              className="text-blue-600"
            />

          </div>

          <div>
            <p className="text-sm text-gray-400 mb-2">
                Dashboard / Goals
            </p>
            <h1 className="text-3xl font-bold text-gray-900">
              Savings Goals
            </h1>

            <p className="text-gray-500 mt-2">
              Track your savings goals, monitor progress,
              and stay on target.
            </p>

          </div>

        </div>

        <button
  onClick={onAdd}
  className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-xl font-medium transition"
>
  + New Goal
</button>

      </div>

    </div>
  );
}