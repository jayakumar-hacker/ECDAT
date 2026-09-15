import { Navigate, Outlet } from "react-router-dom";
import { isAuthenticated } from "../services/api";

export default function ProtectedRoute() {
  if (!isAuthenticated()) {
    return <Navigate to="/login" replace />;
  }
  return <Outlet />;
}
