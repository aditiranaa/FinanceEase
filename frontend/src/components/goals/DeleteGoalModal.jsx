export default function DeleteGoalModal({
  open,
  onClose,
  onConfirm,
  goal,
}) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">

      <div className="bg-white rounded-2xl shadow-xl w-full max-w-md p-6">

        <h2 className="text-2xl font-bold">
          Delete Goal?
        </h2>

        <p className="mt-3 text-gray-500">
          Are you sure you want to delete
          <span className="font-semibold">
            {" "}
            {goal?.title}
          </span>
          ?
        </p>

        <p className="text-sm text-red-500 mt-2">
          This action cannot be undone.
        </p>

        <div className="flex justify-end gap-3 mt-8">

          <button
            onClick={onClose}
            className="px-5 py-2 rounded-xl border"
          >
            Cancel
          </button>

          <button
            onClick={onConfirm}
            className="px-5 py-2 rounded-xl bg-red-600 text-white hover:bg-red-700"
          >
            Delete
          </button>

        </div>

      </div>

    </div>
  );
}