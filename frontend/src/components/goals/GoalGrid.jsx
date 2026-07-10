import GoalCard from "./GoalCard";

export default function GoalGrid({
  goals,
  onEdit,
  onDelete,
  onComplete,
}) {
  if (goals.length === 0) {
    return null;
  }

  return (
    <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-3">
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