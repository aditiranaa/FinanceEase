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

import {
  getTransactions,
} from "../../api/authApi";

const Dashboard = () => {

  const [transactions,
    setTransactions] =
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

  }, []);

  return (

    <div className="flex">

      <Sidebar />

      <div
        className="
          flex-1
          p-6
          bg-gray-100
          min-h-screen
        "
      >

        <Navbar />

        <StatsCards
          balance={balance}
          income={income}
          expenses={expenses}
          savings={savings}
          BudgetManager 
        />

        <AddTransaction
  fetchTransactions={
    fetchTransactions
  }
/>

<BudgetManager
  transactions={transactions}
/>
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
      </div>

    </div>
  );
};

export default Dashboard;