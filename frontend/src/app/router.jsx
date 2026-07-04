import { createBrowserRouter } from "react-router-dom";

import Login from "../pages/auth/Login";
import Register from "../pages/auth/Register";

import Dashboard from "../pages/dashboard/Dashboard";
import Transactions from "../pages/transactions/Transactions";
import Budgets from "../pages/budgets/Budgets";
import Goals from "../pages/goals/Goals";
import Analytics from "../pages/analytics/Analytics";
import Profile from "../pages/profile/Profile";

import ProtectedRoute from "../routes/ProtectedRoute";

const router = createBrowserRouter([
  {
    path: "/",
    element: <Login />,
  },

  {
    path: "/register",
    element: <Register />,
  },

  {
    path: "/dashboard",
    element: (
      <ProtectedRoute>
        <Dashboard />
      </ProtectedRoute>
    ),
  },

  {
    path: "/transactions",
    element: (
      <ProtectedRoute>
        <Transactions />
      </ProtectedRoute>
    ),
  },

  {
    path: "/budgets",
    element: (
      <ProtectedRoute>
        <Budgets />
      </ProtectedRoute>
    ),
  },

  {
    path: "/goals",
    element: (
      <ProtectedRoute>
        <Goals />
      </ProtectedRoute>
    ),
  },

  {
    path: "/analytics",
    element: (
      <ProtectedRoute>
        <Analytics />
      </ProtectedRoute>
    ),
  },

  {
    path: "/profile",
    element: (
      <ProtectedRoute>
        <Profile />
      </ProtectedRoute>
    ),
  },
]);

export default router;