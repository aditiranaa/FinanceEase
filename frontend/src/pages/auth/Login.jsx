import { useState } from "react";
import { useNavigate } from "react-router-dom";

import { loginUser } from "../../api/authApi";
import { useAuth } from "../../context/AuthContext";

const Login = () => {

  const navigate = useNavigate();

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

      const data =
        await loginUser(formData);

      console.log(
        "Login Response:",
        data
      );

      login(data.token);

      navigate("/dashboard");

    }

    catch (error) {

      console.error(error);

      if (error.response) {

        console.log(
          "Status:",
          error.response.status
        );

        console.log(
          "Data:",
          error.response.data
        );

      }

      else {

        console.log(
          error.message
        );

      }

    }

  };

  return (

    <div>

      <h1>Login</h1>

      <form
        onSubmit={handleSubmit}
      >

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

        <button
          type="submit"
        >
          Login
        </button>

      </form>

    </div>

  );

};

export default Login;