import {
  useState,
} from "react";

const ChangePassword = () => {

  const [
    currentPassword,
    setCurrentPassword,
  ] = useState("");

  const [
    newPassword,
    setNewPassword,
  ] = useState("");

  const handleSubmit =
    (e) => {

      e.preventDefault();

      alert(
        "Backend coming next!"
      );

    };

  return (

    <div
      className="
        bg-white
        dark:bg-gray-900
        rounded-xl
        shadow
        p-6
        mt-6
      "
    >

      <h2
        className="
          text-2xl
          font-bold
          mb-4
          dark:text-white
        "
      >
        Change Password
      </h2>

      <form
        onSubmit={handleSubmit}
        className="space-y-4"
      >

        <input
          type="password"
          placeholder="Current Password"
          value={currentPassword}
          onChange={(e)=>
            setCurrentPassword(
              e.target.value
            )
          }
          className="
            w-full
            border
            rounded
            p-3
          "
        />

        <input
          type="password"
          placeholder="New Password"
          value={newPassword}
          onChange={(e)=>
            setNewPassword(
              e.target.value
            )
          }
          className="
            w-full
            border
            rounded
            p-3
          "
        />

        <button
          className="
            bg-blue-500
            text-white
            px-5
            py-3
            rounded
          "
        >
          Update Password
        </button>

      </form>

    </div>

  );

};

export default ChangePassword;