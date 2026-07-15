import { useEffect, useState } from "react";

import AppLayout from "../../components/layout/AppLayout";

import HeroBanner from "../../components/dashboard/HeroBanner";
import StatsCards from "../../components/dashboard/StatsCards";
import AICoach from "../../components/dashboard/AICoach";
import AddTransaction from "../../components/dashboard/AddTransaction";
import RecentTransactions from "../../components/dashboard/RecentTransactions";
import ExpenseChart from "../../components/dashboard/ExpenseChart";
import MonthlyTrendChart from "../../components/dashboard/MonthlyTrendChart";
import ExportTransactions from "../../components/dashboard/ExportTransactions";
import BudgetAlerts from "../../components/budgets/BudgetAlerts";
import SavingsGoals from "../../components/dashboard/SavingsGoals";
import AIInsights from "../../components/dashboard/AIInsights";
import RecurringTransactions from "../../components/dashboard/RecurringTransactions";

import {
  getTransactions,
  getBudgets,
} from "../../api/authApi";

const Dashboard = () => {
  const [transactions, setTransactions] = useState([]);
  const [budgets, setBudgets] = useState([]);

  const income = transactions
    .filter((transaction) => transaction.amount > 0)
    .reduce(
      (acc, transaction) => acc + Number(transaction.amount),
      0
    );

  const expenses = transactions
    .filter((transaction) => transaction.amount < 0)
    .reduce(
      (acc, transaction) => acc + Number(transaction.amount),
      0
    );

  const balance = income + expenses;
  const savings = balance;

  const fetchTransactions = async () => {
    try {
      const data = await getTransactions();
      setTransactions(data);
    } catch (error) {
      console.log(error);
    }
  };

  const fetchBudgets = async () => {
    try {
      const data = await getBudgets();
      setBudgets(data);
    } catch (error) {
      console.log(error);
    }
  };

  useEffect(() => {
    fetchTransactions();
    fetchBudgets();
  }, []);

  return (
    <AppLayout>
      <div className="space-y-8">
        {/* Hero */}
        <HeroBanner balance={balance} />

        {/* Statistics */}
        <StatsCards
          balance={balance}
          income={income}
          expenses={expenses}
          savings={savings}
        />

        {/* Main Dashboard Grid */}
        <div className="grid grid-cols-1 gap-8 xl:grid-cols-12">
          {/* Left */}
          <div className="space-y-8 xl:col-span-8">
            <ExpenseChart
              transactions={transactions}
            />

            <MonthlyTrendChart
              transactions={transactions}
            />

            <RecentTransactions
              transactions={transactions}
              fetchTransactions={fetchTransactions}
            />
          </div>

          {/* Right */}
          <div className="space-y-8 xl:col-span-4">
            <AICoach />

            <AddTransaction
              fetchTransactions={fetchTransactions}
            />

            <BudgetAlerts budgets={budgets} />

            <SavingsGoals />

            <RecurringTransactions />

            <ExportTransactions
              transactions={transactions}
            />
          </div>
        </div>

        {/* Bottom */}
        <AIInsights />
      </div>
    </AppLayout>
  );
};

export default Dashboard;