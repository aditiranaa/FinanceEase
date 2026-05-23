import { useNavigate } from "react-router-dom";

import { useAuth } from "../../context/AuthContext";

const Navbar = () => {

  const navigate = useNavigate();

  const { logout } = useAuth();

  const handleLogout = () => {

    logout();

    navigate("/");

  };

  return (
    <div
      className="
        flex
        justify-between
        items-center
        bg-white
        p-4
        rounded-lg
        shadow
      "
    >

      <h2 className="text-2xl font-semibold">
        Dashboard
      </h2>

      <button
        onClick={handleLogout}
        className="
          bg-red-500
          text-white
          px-4
          py-2
          rounded
          hover:bg-red-600
        "
      >
        Logout
      </button>

    </div>
  );
};

export default Navbar;