import { ReplayResponse } from "@google/genai";
import API from "./axios";

export const loginUser = async (formData) => {
  const response = await API.post(
    "/auth/login",
    formData
  );
  return response.data;
  };

  export const getSubscriptions =
  async () => {

  const response =
    await API.get(
      "/subscriptions"
    );

  return response.data;

};

export const getAIInsight =
async (prompt) => {

  const response =
    await API.post(
      "/ai-insight",
      {
        prompt,
      }
    );

  return response.data;

};

export const createSubscription =
  async (formData) => {

  const response =
    await API.post(
      "/subscriptions",
      formData
    );

  return response.data;

};

  export const getTransactions =
  async () => {

  const response =
    await API.get(
      "/transactions"
    );

  return response.data;
};

  export const createTransaction =
  async (formData) => {

  const response =
    await API.post(
      "/transactions",
      formData
    );

  return response.data;
};

  export const registerUser =
  async (formData) => {

  const response = await API.post(
    "/auth/register",
    formData
  );

  return response.data;
};

export const deleteTransaction = async (id) => {
  const response = await API.delete(
    `/transactions/${id}`
  );

  return response.data;
};

export const getGoals =
  async () => {

  const response =
    await API.get(
      "/goals"
    );

  return response.data;

};

export const createGoal =
  async (formData) => {

  const response =
    await API.post(
      "/goals",
      formData
    );

  return response.data;

};

export const deleteBudget =
  async (id) => {

  const response =
    await API.delete(
      `/budgets/${id}`
    );

  return response.data;

};

export const getAIHistory =
async () => {

  const response =
    await API.get(
      "/ai-insight/history"
    );

  return response.data;

};

export const updateTransaction =
  async (id, formData) => {

  const response =
    await API.put(
      `/transactions/${id}`,
      formData
    );

  return response.data;

};

export const getBudgets =
  async () => {

  const response =
    await API.get(
      "/budgets"
    );

  return response.data;
};

export const createBudget =
  async (formData) => {

  const response =
    await API.post(
      "/budgets",
      formData
    );
    
  return response.data;
  };

export const getNotifications =
  async () => {

  const response =
    await API.get(
      "/notifications"
    );

  return response.data;
};
