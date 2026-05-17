import { useState } from "react";

import { loginUser } from "../../api/authApi";

import { useAuth }
from "../../context/AuthContext";

const Login = () => {
  const { login } = useAuth();
  const [formData, setFormData] = useState({
    email: "",
    password: "",
  });

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

 const handleSubmit = async (e) => {
  e.preventDefault();

  try {
    const data = await loginUser(formData);

    console.log(data);

    login(data.token);

  } catch (error) {
    console.log(error);
  }
};

  return (
    <div>
      <h1>Login</h1>

      <form onSubmit={handleSubmit}>
        <div>
          <input
            type="email"
            name="email"
            placeholder="Enter email"
            value={formData.email}
            onChange={handleChange}
          />
        </div>

        <br />

        <div>
          <input
            type="password"
            name="password"
            placeholder="Enter password"
            value={formData.password}
            onChange={handleChange}
          />
        </div>

        <br />

        <button type="submit">
          Login
        </button>
      </form>
    </div>
  );
};

export default Login;