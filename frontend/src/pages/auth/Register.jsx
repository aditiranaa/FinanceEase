import { useState } from "react";

import { useNavigate } from "react-router-dom";

import { useAuth } from "../../context/AuthContext";

import {
  registerUser,
} from "../../api/authApi";

const Register = () => {

  const navigate = useNavigate();

  const { login } = useAuth();

  const [formData, setFormData] =
    useState({
      name: "",
      email: "",
      password: "",
    });

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]:
        e.target.value,
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {

      const data =
        await registerUser(formData);

      login(data.token);

      navigate("/dashboard");

    } catch (error) {
      console.log(error);
    }
  };

  return (
    <div>

      <h1>Register</h1>

      <form onSubmit={handleSubmit}>

        <div>
          <input
            type="text"
            name="name"
            placeholder="Enter name"
            value={formData.name}
            onChange={handleChange}
          />
        </div>

        <br />

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
          Register
        </button>

      </form>

    </div>
  );
};

export default Register;