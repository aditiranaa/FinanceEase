import API from "../api/axios";

const BASE = "/subscriptions";

export const getSubscriptions = async () => {
  const res = await API.get(BASE);
  return res.data;
};

export const createSubscription = async (data) => {
  const res = await API.post(BASE, data);
  return res.data;
};

export const updateSubscription = async (id, data) => {
  const res = await API.put(
    `${BASE}/${id}`,
    data
  );

  return res.data;
};

export const deleteSubscription = async (id) => {
  const res = await API.delete(
    `${BASE}/${id}`
  );

  return res.data;
};