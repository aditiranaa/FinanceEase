import Sidebar from "./Sidebar";
import Navbar from "./Navbar";

export default function AppLayout({ children }) {
  return (
    <div className="flex min-h-screen bg-gray-100 dark:bg-gray-950">
      <Sidebar />

      <main className="flex-1 overflow-x-hidden">
        <div className="px-5 pt-2 pb-4">
          <Navbar />

          <div className="mt-2">
            {children}
          </div>
        </div>
      </main>
    </div>
  );
}