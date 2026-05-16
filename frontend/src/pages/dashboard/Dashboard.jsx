import { useEffect } from "react";

import {
  getAIInsight,
} from "../../api/authApi";

const Dashboard = () => {
  useEffect(() => {
    const fetchInsight = async () => {
      try {
        const data =
          await getAIInsight();

        console.log(data);
      } catch (error) {
        console.log(error);
      }
    };

    fetchInsight();
  }, []);

  return (
    <div>
      <h1>Dashboard</h1>
    </div>
  );
};

export default Dashboard;