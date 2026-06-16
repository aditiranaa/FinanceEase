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

ReactDOM.createRoot(
  document.getElementById("root")
).render(
  <React.StrictMode>
    <AuthProvider>
  <ThemeProvider>
    <RouterProvider
      router={router}
    />
  </ThemeProvider>
</AuthProvider>
  </React.StrictMode>
);