import API from "../api/axios";

const BASE = "/budgets";

export const getBudgets = async () => {
  const res = await API.get(BASE);
  return res.data;
};

export const getBudget = async (id) => {
  const res = await API.get(`${BASE}/${id}`);
  return res.data;
};

export const createBudget = async (data) => {
  const res = await API.post(BASE, data);
  return res.data.budget;
};

export const updateBudget = async (id, data) => {
  const res = await API.put(`${BASE}/${id}`, data);
  return res.data.budget;
};

export const deleteBudget = async (id) => {
  const res = await API.delete(`${BASE}/${id}`);
  return res.data;
};

export const getBudgetSummary = async () => {
  const res = await API.get(`${BASE}/summary`);
  return res.data;
};