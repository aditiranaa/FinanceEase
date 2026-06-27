const ProfileCard = ({
  profile,
}) => {

  return (

    <div
      className="
        bg-white
        dark:bg-gray-900
        rounded-xl
        shadow
        p-6
      "
    >

      <h2
        className="
          text-2xl
          font-bold
          mb-6
          dark:text-white
        "
      >
        My Profile
      </h2>

      <p className="dark:text-gray-300">
        <strong>Name:</strong> {profile.name}
      </p>

      <br />

      <p className="dark:text-gray-300">
        <strong>Email:</strong> {profile.email}
      </p>

      <br />

      <p className="dark:text-gray-300">
        <strong>Member Since:</strong>{" "}
        {
          new Date(
            profile.created_at
          ).toLocaleDateString("en-IN")
        }
      </p>

    </div>

  );

};

export default ProfileCard;