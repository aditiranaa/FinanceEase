import { useEffect } from "react";
import { X, Target } from "lucide-react";

export default function GoalModal({
  open,
  editingGoal,
  onClose,
  children,
}) {
  useEffect(() => {
    if (!open) return;

    const handleKeyDown = (event) => {
      if (event.key === "Escape") {
        onClose();
      }
    };

    document.addEventListener("keydown", handleKeyDown);

    return () =>
      document.removeEventListener(
        "keydown",
        handleKeyDown
      );
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="
        fixed
        inset-0
        z-50
        flex
        items-center
        justify-center
        bg-black/50
        backdrop-blur-sm
        p-4
      "
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="
          w-full
          max-w-2xl
          overflow-hidden
          rounded-2xl
          border
          border-gray-200
          dark:border-gray-700
          bg-white
          dark:bg-gray-900
          shadow-2xl
        "
      >
        <div
          className="
            flex
            items-start
            justify-between
            border-b
            border-gray-200
            dark:border-gray-700
            px-8
            py-6
          "
        >
          <div className="flex items-start gap-4">
            <div
              className="
                flex
                h-12
                w-12
                items-center
                justify-center
                rounded-2xl
                bg-blue-100
                dark:bg-blue-900/30
              "
            >
              <Target
                size={22}
                className="text-blue-600"
              />
            </div>

            <div>
              <h2 className="text-lg font-bold text-gray-900 dark:text-white">
                {editingGoal
                  ? "Edit Goal"
                  : "Create Goal"}
              </h2>

              <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                Fill in the details below to
                save your financial goal.
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="
              rounded-xl
              p-2
              text-gray-500
              transition
              hover:bg-gray-100
              hover:text-gray-900
              dark:hover:bg-gray-800
              dark:hover:text-white
            "
          >
            <X size={22} />
          </button>
        </div>

        <div className="max-h-[75vh] overflow-y-auto p-8">
          {children}
        </div>
      </div>
    </div>
  );
}