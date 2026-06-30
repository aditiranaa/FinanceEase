import {
  useEffect,
  useState,
} from "react";

import Sidebar
from "../../components/layout/Sidebar";

import Navbar
from "../../components/layout/Navbar";

import StatsCards
from "../../components/dashboard/StatsCards";

import AddTransaction
from "../../components/dashboard/AddTransaction";

import RecentTransactions
from "../../components/dashboard/RecentTransactions";

import ExpenseChart
from "../../components/dashboard/ExpenseChart";

import BudgetManager
from "../../components/dashboard/BudgetManager";

import MonthlyTrendChart
from "../../components/dashboard/MonthlyTrendChart";

import AIInsights
from "../../components/dashboard/AIInsights";

import ExportTransactions
from "../../components/dashboard/ExportTransactions";

import RecurringTransactions
from "../../components/dashboard/RecurringTransactions";

import BudgetAlerts
from "../../components/dashboard/BudgetAlerts";

import SavingsGoals
from "../../components/dashboard/SavingsGoals";

import {
  getTransactions,
  getBudgets,
} from "../../api/authApi";

import AICoach
from "../../components/dashboard/AICoach";

const Dashboard = () => {

  const [transactions,
    setTransactions] =
      useState([]);

  const [budgets, setBudgets] =
  useState([]);

  const income =
  transactions
    .filter(
      (transaction) =>
        transaction.amount > 0
    )
    .reduce(
      (acc, transaction) =>
        acc + Number(transaction.amount),
      0
    );

const expenses =
  transactions
    .filter(
      (transaction) =>
        transaction.amount < 0
    )
    .reduce(
      (acc, transaction) =>
        acc + Number(transaction.amount),
      0
    );

const balance =
  income + expenses;

const savings =
  balance;

  const fetchTransactions =
    async () => {

    try {

      const data =
        await getTransactions();

      setTransactions(data);

    } catch (error) {

      console.log(error);

    }
  };

  useEffect(() => {

  fetchTransactions();

  fetchBudgets();

}, []);

  const fetchBudgets =
  async () => {

    try {

      const data =
        await getBudgets();

      setBudgets(data);

    } catch (error) {

      console.log(error);

    }

  };

  return (

    <div
  className="
    flex
    flex-col
    md:flex-row
  "
>

      <Sidebar />

      <div
        className="
          flex-1
          p-6
          bg-gray-100
          dark:bg-gray-800
          min-h-screen
          transition-colors
        "
      >

        <Navbar />

        <StatsCards
          balance={balance}
          income={income}
          expenses={expenses}
          savings={savings}
        />

        <AICoach />
        
        <AddTransaction
          fetchTransactions={
          fetchTransactions
        }
        />

        <BudgetManager
          transactions={transactions}
        />
        <RecurringTransactions />
        
        <RecentTransactions
          transactions={transactions}
          fetchTransactions={fetchTransactions}
        />

        <ExpenseChart
          transactions={transactions}
        />

        <MonthlyTrendChart
          transactions={transactions}
        />

        <ExportTransactions
          transactions={transactions}
        />

        <BudgetAlerts
          budgets={budgets}
          transactions={transactions}
        />
        <SavingsGoals />

        <AIInsights />
      </div>

    </div>
  );
};

export default Dashboard;