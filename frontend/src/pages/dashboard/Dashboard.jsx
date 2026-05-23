import Sidebar from "../../components/layout/Sidebar";

import Navbar from "../../components/layout/Navbar";

import StatsCards from "../../components/dashboard/StatsCards";

const Dashboard = () => {
  return (
    <div className="flex">

      <Sidebar />

      <div className="flex-1 p-6 bg-gray-100 min-h-screen">

        <Navbar />
        <StatsCards />
      </div>

    </div>
  );
};

export default Dashboard;