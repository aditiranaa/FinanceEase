import { useEffect } from "react";

import { testBackend } from "../../api/authApi";

const Dashboard = () => {
  useEffect(() => {
    const fetchData = async () => {
      try {
        const data = await testBackend();

        console.log(data);
      } catch (error) {
        console.log(error);
      }
    };

    fetchData();
  }, []);

  return (
    <div>
      <h1>Dashboard</h1>
    </div>
  );
};

export default Dashboard;