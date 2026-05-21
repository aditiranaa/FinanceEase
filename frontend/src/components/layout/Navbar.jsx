import { useAuth } from "../../context/AuthContext";

const Navbar = () => {

  const { logout } = useAuth();

  return (
    <div
      style={{
        display: "flex",
        justifyContent:
          "space-between",
        padding: "20px",
        borderBottom:
          "1px solid #ddd",
      }}
    >
      <h2>Dashboard</h2>

      <button onClick={logout}>
        Logout
      </button>
    </div>
  );
};

export default Navbar;