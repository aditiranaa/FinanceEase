import API from "../api/axios";

const BASE = "/analytics";

export const getOverview = async () => {
  const res = await API.get(`${BASE}/overview`);
  return res.data;
};

export const getExpenseByCategory = async () => {
  const res = await API.get(
    `${BASE}/expenses/category`
  );
  return res.data;
};

export const getMonthlyTrend = async () => {
  const res = await API.get(
    `${BASE}/monthly-trend`
  );
  return res.data;
};

export const getSavingsTrend = async () => {
  const res = await API.get(
    `${BASE}/savings-trend`
  );
  return res.data;
};