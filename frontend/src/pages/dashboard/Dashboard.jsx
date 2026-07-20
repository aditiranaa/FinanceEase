import { useEffect, useState } from "react";

import { motion } from "framer-motion";
import Sidebar from "../../components/layout/Sidebar";
import Navbar from "../../components/layout/Navbar";

import HeroBanner from "../../components/dashboard/HeroBanner";
import StatsCards from "../../components/dashboard/StatsCards";
import ExpenseChart from "../../components/dashboard/ExpenseChart";
import AIInsights from "../../components/dashboard/AIInsights";
import RecentTransactions from "../../components/dashboard/RecentTransactions";
import SavingsGoals from "../../components/dashboard/SavingsGoals";

import { getTransactions } from "../../api/authApi";

const Dashboard = () => {
  const [transactions, setTransactions] = useState([]);

  const fetchTransactions = async () => {
    try {
      const data = await getTransactions();
      setTransactions(data);
    } catch (error) {
      console.error(error);
    }
  };

  useEffect(() => {
    fetchTransactions();
  }, []);

  const income = transactions
    .filter((t) => Number(t.amount) > 0)
    .reduce((sum, t) => sum + Number(t.amount), 0);

  const expenses = transactions
    .filter((t) => Number(t.amount) < 0)
    .reduce((sum, t) => sum + Number(t.amount), 0);

  const balance = income + expenses;
  const savings = income - Math.abs(expenses);

  return (
    <div className="flex min-h-screen bg-slate-50 dark:bg-slate-950">
      <Sidebar />

      <main className="flex-1 overflow-x-hidden">
        <Navbar />

        <div className="mx-auto max-w-7xl space-y-8 px-6 py-8">
          <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4 }}
            >
              <HeroBanner balance={balance} />
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.1 }}
            >
              <StatsCards
                balance={balance}
                income={income}
                expenses={expenses}
                savings={savings}
              />
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.2 }}
            >
              <div className="grid grid-cols-1 gap-8 xl:grid-cols-3">
                <div className="xl:col-span-2">
                  <ExpenseChart transactions={transactions} />
                </div>

                <AIInsights />
              </div>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.3 }}
            >
              <RecentTransactions
                transactions={transactions}
                fetchTransactions={fetchTransactions}
              />
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.4 }}
            >
              <SavingsGoals />
            </motion.div>
        </div>
      </main>
    </div>
  );
};

export default Dashboard;