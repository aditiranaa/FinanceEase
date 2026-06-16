import { useState } from "react";

const Profile = () => {

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

  const handleSubmit =
    (e) => {

      e.preventDefault();

      alert(
        "Profile updated"
      );

    };

  return (

    <div
      className="
        bg-white
        p-8
        rounded-2xl
        shadow-sm
      "
    >

      <h1
        className="
          text-3xl
          font-bold
          mb-8
        "
      >
        Profile
      </h1>

      <form
        onSubmit={handleSubmit}
        className="space-y-5"
      >

        <input
          type="text"
          name="name"
          placeholder="Name"
          value={formData.name}
          onChange={handleChange}
          className="
            w-full
            border
            p-3
            rounded-lg
          "
        />

        <input
          type="email"
          name="email"
          placeholder="Email"
          value={formData.email}
          onChange={handleChange}
          className="
            w-full
            border
            p-3
            rounded-lg
          "
        />

        <input
          type="password"
          name="password"
          placeholder="New Password"
          value={formData.password}
          onChange={handleChange}
          className="
            w-full
            border
            p-3
            rounded-lg
          "
        />

        <button
          type="submit"
          className="
            bg-green-500
            text-white
            px-5
            py-3
            rounded-lg
            hover:bg-green-600
          "
        >
          Save Changes
        </button>

      </form>

    </div>

  );

};

export default Profile;
