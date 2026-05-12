import API from "./axios";

export const testBackend = async () => {
  const response = await API.get("/test");

  return response.data;
};