import {
  useEffect,
  useState,
} from "react";

import {
  getProfile,
} from "../api/authApi";

const Profile = () => {

  const [profile,
    setProfile] =
    useState(null);

  useEffect(() => {

    fetchProfile();

  }, []);

  const fetchProfile =
    async () => {

      try {

        const data =
          await getProfile();

        setProfile(data);

      }

      catch (error) {

        console.log(error);

      }

    };

  if (!profile) {

    return (
      <p
        className="
          p-6
        "
      >
        Loading...
      </p>
    );

  }

  return (

    <div
      className="
        p-8
      "
    >

      <h1
        className="
          text-3xl
          font-bold
          mb-6
        "
      >
        My Profile
      </h1>

      <div
        className="
          bg-white
          dark:bg-gray-900
          rounded-xl
          shadow
          p-6
        "
      >

        <p>
          <strong>Name:</strong>{" "}
          {profile.name}
        </p>

        <br />

        <p>
          <strong>Email:</strong>{" "}
          {profile.email}
        </p>

        <br />

        <p>
          <strong>Member Since:</strong>{" "}
          {
            new Date(
              profile.created_at
            ).toLocaleDateString(
              "en-IN"
            )
          }
        </p>

      </div>

    </div>

  );

};

export default Profile;