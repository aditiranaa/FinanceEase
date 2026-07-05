import API from "../api/axios";

const BASE = "/goals";

export const getGoals = async () => {
  const res = await API.get(BASE);
  return res.data;
};

export const getGoal = async (id) => {
  const res = await API.get(`${BASE}/${id}`);
  return res.data;
};

export const createGoal = async (data) => {
  const res = await API.post(BASE, data);
  return res.data;
};

export const updateGoal = async (id, data) => {
  const res = await API.put(`${BASE}/${id}`, data);
  return res.data;
};

export const deleteGoal = async (id) => {
  const res = await API.delete(`${BASE}/${id}`);
  return res.data;
};

export const markGoalComplete = async (id) => {
  const res = await API.put(`${BASE}/${id}`, { completed: true });
  return res.data;
};
