import { useState } from "react";
import Sidebar from "./Sidebar";
import Navbar from "./Navbar";

export default function AppLayout({ children }) {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div className="min-h-screen bg-gray-100 dark:bg-gray-950">
      <Sidebar
        collapsed={collapsed}
        setCollapsed={setCollapsed}
      />

      <main
        className={`transition-[margin] duration-300 ${
          collapsed ? "md:ml-20" : "md:ml-72"
        }`}
      >
        <div className="px-6 pt-2 pb-4">
          <Navbar />
          {children}
        </div>
      </main>
    </div>
  );
}