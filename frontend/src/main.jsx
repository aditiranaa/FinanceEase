import React from "react";
import ReactDOM from "react-dom/client";

import { AuthProvider }
from "./context/AuthContext";

import { RouterProvider } from "react-router-dom";

import router from "./app/router";

import "./index.css";

import {
  ThemeProvider,
} from "./context/ThemeContext";

import { Toaster } from "react-hot-toast";


ReactDOM.createRoot(
  document.getElementById("root")
).render(
  <React.StrictMode>
    <AuthProvider>
  <ThemeProvider>
    <RouterProvider
      router={router}
    />
    <Toaster
      position="top-right"
      toastOptions={{
        duration: 2500,
      }}
    />
  </ThemeProvider>
</AuthProvider>
  </React.StrictMode>
);