import {
  Bell,
  Search,
  User,
  Moon,
  Sun,
} from "lucide-react";


import { useNavigate } 
from "react-router-dom";

import { useAuth } 
from "../../context/AuthContext";

import { useTheme } 
from "../../context/ThemeContext";

const Navbar = () => {

  const navigate =
    useNavigate();

  const { logout } =
    useAuth();
  
  const {
    darkMode,
    setDarkMode 
  } = useTheme();

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
        transition-colors
      "
    >

      <div>

          <h1
          className="
            text-3xl
            font-bold
            text-gray-800
            dark:text-white
          "
        >
          Dashboard
        </h1>

        <p
          className="
            text-gray-500
            dark:text-gray-300
          "
        >
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
            dark:text-gray-300
            cursor-pointer
          "
        />

        <Bell
          className="
            text-gray-500
            dark:text-gray-300
            cursor-pointer
          "
        />

        <button
          onClick={() =>
            setDarkMode(
              !darkMode
            )
          }
          className="
            bg-gray-200
            dark:bg-gray-700
            p-2
            rounded-full
            transition
          "
        >

          {
            darkMode
              ? <Sun
                  size={20}
                  className="text-yellow-400"
                />
              : <Moon
                  size={20}
                  className="text-gray-700"
                />
          }

        </button>

        <div
          className="
            bg-gray-100
            dark:bg-gray-700
            p-2
            rounded-full
          "
        >

          <User
            size={22}
            className="
              dark:text-white
            "
          />

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