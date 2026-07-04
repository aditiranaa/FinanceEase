import Navbar from "../../components/layout/Navbar";
import Sidebar from "../../components/layout/Sidebar";

const Analytics = () => {

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

        <div
          className="
            mt-8
            bg-white
            rounded-2xl
            shadow-sm
            p-8
          "
        >

          <h1
            className="
              text-3xl
              font-bold
            "
          >
            📊 Analytics
          </h1>

          <p
            className="
              mt-4
              text-gray-500
            "
          >
            Analytics page is under development.
          </p>

        </div>

      </div>

    </div>

  );

};

export default Analytics;