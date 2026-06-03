import API from "./axios";

export const loginUser = async (formData) => {
  const response = await API.post(
    "/auth/login",
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

export const getAIInsight = async () => {
  const response = await API.post(
    "/ai-insight"
  );

  return response.data;
};
