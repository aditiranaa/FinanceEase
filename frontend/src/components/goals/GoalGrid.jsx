import GoalCard from "./GoalCard";

export default function GoalGrid({
  goals,
  onEdit,
  onDelete,
  onComplete,
}) {
  if (goals.length === 0) {
    return (
      <div className="rounded-3xl bg-white border border-dashed border-gray-300 p-20 text-center">

        <div className="text-7xl">
            🎯
        </div>

        <h2 className="mt-6 text-3xl font-bold">
            No Goals Yet
        </h2>

        <p className="mt-3 text-gray-500">
            Start your financial journey by creating your first savings goal.
        </p>

</div>
    );
  }

  return (
    <div className="grid gap-6 lg:grid-cols-2 xl:grid-cols-3">
    {goals.map((goal) => (
        <GoalCard
          key={goal.id}
          goal={goal}
          onEdit={onEdit}
          onDelete={onDelete}
          onComplete={onComplete}
        />
      ))}
    </div>
  );
}