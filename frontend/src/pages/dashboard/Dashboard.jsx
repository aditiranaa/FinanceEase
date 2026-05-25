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

import {
  getTransactions,
} from "../../api/authApi";

const Dashboard = () => {

  const [transactions,
    setTransactions] =
      useState([]);

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

        <StatsCards />

        <AddTransaction
          fetchTransactions={
            fetchTransactions
          }
        />

        <RecentTransactions
          transactions={
            transactions
          }
        />

      </div>

    </div>
  );
};

export default Dashboard;