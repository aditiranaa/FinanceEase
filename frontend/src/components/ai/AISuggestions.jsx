import { Trash2, History } from "lucide-react";

export default function AIHistory({
  history,
  removeHistory,
}) {
  return (
    <div className="bg-white dark:bg-gray-900 rounded-xl shadow p-6">

      <div className="flex items-center gap-2 mb-5">
        <History className="text-blue-600" />
        <h2 className="text-xl font-bold">
          AI History
        </h2>
      </div>

      {history.length === 0 ? (
        <p className="text-gray-500">
          No previous analyses.
        </p>
      ) : (
        <div className="space-y-4">

          {history.map((item) => (
            <div
              key={item.id}
              className="border rounded-lg p-4"
            >
              <p className="text-sm text-gray-500">
                {new Date(
                  item.created_at
                ).toLocaleString()}
              </p>

              <p className="mt-3 whitespace-pre-wrap">
                {item.response}
              </p>

              <button
                onClick={() =>
                  removeHistory(item.id)
                }
                className="mt-4 flex items-center gap-2 text-red-600 hover:text-red-700"
              >
                <Trash2 size={16} />
                Delete
              </button>
            </div>
          ))}

        </div>
      )}

    </div>
  );
}