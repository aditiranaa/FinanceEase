import { Trash2 } from "lucide-react";

export default function DeleteGoalModal({
  open,
  goal,
  onClose,
  onConfirm,
}) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">

      <div className="bg-white rounded-3xl w-full max-w-md p-8 shadow-2xl">

        <div className="flex justify-center">

          <div className="h-16 w-16 rounded-full bg-red-100 flex items-center justify-center">

            <Trash2
              size={30}
              className="text-red-600"
            />

          </div>

        </div>

        <h2 className="mt-6 text-center text-2xl font-bold">
          Delete Goal?
        </h2>

        <p className="mt-3 text-center text-gray-500">
          "{goal?.title}" will be permanently deleted.
        </p>

        <div className="mt-4 flex gap-4">

          <button
            onClick={onClose}
            className="flex-1 rounded-xl border py-3"
          >
            Cancel
          </button>

          <button
            onClick={onConfirm}
            className="flex-1 rounded-xl bg-red-600 text-white py-3 hover:bg-red-700"
          >
            Delete
          </button>

        </div>

      </div>

    </div>
  );
}