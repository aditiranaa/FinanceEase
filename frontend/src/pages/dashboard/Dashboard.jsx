import Sidebar from "../../components/layout/Sidebar";

import Navbar from "../../components/layout/Navbar";

import StatsCards from "../../components/dashboard/StatsCards";

import RecentTransactions from "../../components/dashboard/RecentTransactions";

import AddTransaction from "../../components/dashboard/AddTransaction";

const Dashboard = () => {
  return (
    <div className="flex">

      <Sidebar />

      <div className="flex-1 p-6 bg-gray-100 min-h-screen">

        <Navbar />

        <StatsCards />

        <RecentTransactions />
        
      </div>

    </div>
  );
};

export default Dashboard;