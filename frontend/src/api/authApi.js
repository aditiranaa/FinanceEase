import API from "./axios";

export const loginUser = async (formData) => {
  const response = await API.post(
    "/auth/login",
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
