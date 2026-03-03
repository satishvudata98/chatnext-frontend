import { Navigate, useLocation } from "react-router-dom";
import type { JSX } from "react";
import { useAuth } from "../context/AuthContext";
import AppLoader from "./AppLoader";

interface Props {
  children: JSX.Element;
}

export default function ProtectedRoute({ children }: Props): JSX.Element {
  const location = useLocation();
  const { user, loading } = useAuth();

  if (loading) {
    return <AppLoader />;
  }

  if (!user) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  return children;
}
