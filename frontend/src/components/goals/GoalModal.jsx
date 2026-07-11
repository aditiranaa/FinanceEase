export default function GoalModal({
  open,
  editingGoal,
  onClose,
  onSubmit,
  children,
}) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-6">

      <div className="w-full max-w-2xl rounded-3xl bg-white shadow-2xl">

        <div className="border-b px-8 py-6 flex items-center justify-between">

          <div>

            <h2 className="text-2xl font-bold">

              {editingGoal
                ? "Edit Goal"
                : "Create Goal"}

            </h2>

            <p className="text-gray-500 mt-1">
              Fill in the details below.
            </p>

          </div>

          <button
            onClick={onClose}
            className="text-2xl text-gray-400 hover:text-gray-700"
          >
            ×
          </button>

        </div>

        <div className="p-8">
          {children}
        </div>

      </div>

    </div>
  );
}