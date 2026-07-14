import {
  useEffect,
  useState,
} from "react";

import {
  getProfile,
} from "../../api/authApi";

import ProfileCard
from "../../components/profile/ProfileCard";

import ChangePassword
from "../../components/profile/ChangePassword";

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
          p-4
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
      bg-gray-100
      dark:bg-gray-800
      min-h-screen
    "
  >

    <ProfileCard
      profile={profile}
    />

    <ChangePassword />

  </div>

);

};

export default Profile;