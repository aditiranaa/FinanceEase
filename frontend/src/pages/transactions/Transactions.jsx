import {
  useEffect,
  useState,
} from "react";

import Sidebar
from "../../components/layout/Sidebar";

import Navbar
from "../../components/layout/Navbar";

import AddTransaction
from "../../components/dashboard/AddTransaction";

import RecentTransactions
from "../../components/dashboard/RecentTransactions";

import ExportTransactions
from "../../components/dashboard/ExportTransactions";

import {
  getTransactions,
} from "../../api/authApi";

const Transactions = () => {

  const [
    transactions,
    setTransactions,
  ] = useState([]);

  const fetchTransactions =
    async () => {

      try {

        const data =
          await getTransactions();

        setTransactions(data);

      }

      catch (error) {

        console.log(error);

      }

    };

  useEffect(() => {

    fetchTransactions();

  }, []);

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
          min-h-screen
        "
      >

        <Navbar />

        <AddTransaction
          fetchTransactions={
            fetchTransactions
          }
        />

        <RecentTransactions
          transactions={
            transactions
          }
          fetchTransactions={
            fetchTransactions
          }
        />

        <ExportTransactions
          transactions={
            transactions
          }
        />

      </div>

    </div>

  );

};

export default Transactions;