import { useState } from "react";
import { motion } from "framer-motion";
import Sidebar from "./Sidebar";
import Navbar from "./Navbar";

export default function AppLayout({ children }) {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div className="relative min-h-screen overflow-hidden bg-slate-50 dark:bg-[#09090B]">

      {/* Background Decorations */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden">

        <div className="absolute -left-40 -top-40 h-96 w-96 rounded-full bg-blue-500/10 blur-3xl" />

        <div className="absolute right-0 top-0 h-[450px] w-[450px] rounded-full bg-indigo-500/10 blur-3xl" />

        <div className="absolute bottom-0 left-1/3 h-80 w-80 rounded-full bg-cyan-400/10 blur-3xl" />

      </div>

      <Sidebar
        collapsed={collapsed}
        setCollapsed={setCollapsed}
      />

      <main
        className={`
          relative
          transition-all
          duration-500
          ease-out
          ${collapsed ? "md:ml-28" : "md:ml-72"}
        `}
      >

        <div className="mx-auto flex min-h-screen max-w-[1700px] flex-col px-6 py-6 lg:px-10">

          <Navbar />

          <motion.div
            initial={{
              opacity: 0,
              y: 16,
            }}
            animate={{
              opacity: 1,
              y: 0,
            }}
            transition={{
              duration: .45,
              ease: "easeOut",
            }}
            className="mt-8 flex-1"
          >
            {children}
          </motion.div>

        </div>

      </main>

    </div>
  );
}