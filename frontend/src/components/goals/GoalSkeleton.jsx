export default function GoalSkeleton() {
  return (
    <div className="bg-white rounded-2xl shadow-sm p-6 animate-pulse">
      <div className="h-5 w-24 bg-gray-200 rounded" />

      <div className="h-8 w-40 bg-gray-200 rounded mt-4" />

      <div className="h-24 w-24 rounded-full bg-gray-200 mx-auto mt-8" />

      <div className="grid grid-cols-3 gap-3 mt-8">
        <div className="h-12 bg-gray-200 rounded" />
        <div className="h-12 bg-gray-200 rounded" />
        <div className="h-12 bg-gray-200 rounded" />
      </div>
    </div>
  );
}