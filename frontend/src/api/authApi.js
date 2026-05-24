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

export const getAIInsight = async () => {
  const response = await API.post(
    "/ai-insight"
  );

  return response.data;
};
