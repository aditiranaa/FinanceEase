import {
  Bell,
  Search,
  User,
} from "lucide-react";

import { useNavigate } from "react-router-dom";

import { useAuth } from "../../context/AuthContext";

const Navbar = () => {

  const navigate =
    useNavigate();

  const { logout } =
    useAuth();

  const handleLogout = () => {

    logout();

    navigate("/");

  };

  return (

    <div
      className="
        bg-white
        rounded-xl
        shadow-sm
        px-6
        py-4
        flex
        justify-between
        items-center
      "
    >

      <div>

        <h1
          className="
            text-3xl
            font-bold
            text-gray-800
          "
        >
          Dashboard
        </h1>

        <p className="text-gray-500">
          Welcome back 👋
        </p>

      </div>

      <div
        className="
          flex
          items-center
          gap-5
        "
      >

        <Search
          className="
            text-gray-500
            cursor-pointer
          "
        />

        <Bell
          className="
            text-gray-500
            cursor-pointer
          "
        />

        <div
          className="
            bg-gray-100
            p-2
            rounded-full
          "
        >
          <User size={22} />
        </div>

        <button
          onClick={handleLogout}
          className="
            bg-red-500
            hover:bg-red-600
            transition
            text-white
            px-4
            py-2
            rounded-lg
          "
        >
          Logout
        </button>

      </div>

    </div>
  );
};

export default Navbar;