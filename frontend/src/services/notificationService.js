import API from "../api/axios";

const BASE = "/notifications";

export const getNotifications = async () => {
  const res = await API.get(BASE);
  return res.data;
};

export const markAsRead = async (id) => {
  const res = await API.put(
    `${BASE}/${id}/read`
  );

  return res.data;
};

export const deleteNotification = async (id) => {
  const res = await API.delete(
    `${BASE}/${id}`
  );

  return res.data;
};