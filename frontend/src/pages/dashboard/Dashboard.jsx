import Sidebar
from "../../components/layout/Sidebar";

import Navbar
from "../../components/layout/Navbar";

import StatsCards
from "../../components/dashboard/StatsCards";

import RecentTransactions
from "../../components/dashboard/RecentTransactions";

const Dashboard = () => {
  return (
    <div
      style={{
        display: "flex",
      }}
    >

      <Sidebar />

      <div
        style={{
          flex: 1,
          padding: "20px",
        }}
      >
        <Navbar />

        <StatsCards />

        <RecentTransactions />
      </div>

    </div>
  );
};

export default Dashboard;