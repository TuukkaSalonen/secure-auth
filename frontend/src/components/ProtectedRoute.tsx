import React, { JSX } from "react";
import { Navigate } from "react-router-dom";
import { useSelector } from "react-redux";
import { RootState } from "../redux/store";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faSpinner } from "@fortawesome/free-solid-svg-icons";

// Interface for the ProtectedRoute component props
export interface ProtectedRouteProps {
  children: JSX.Element;
}

// ProtectedRoute component to prevent access from unauthenticated users
const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children }) => {
  const auth = useSelector((state: RootState) => state.auth);
  const loading = useSelector((state: RootState) => state.auth.loading);

  if (loading) {
    return (
      <div>
        <FontAwesomeIcon icon={faSpinner} spin size="3x" />
      </div>
    );
  }

  // If the user is not authenticated, redirect to the home page
  if (!auth.isAuthenticated) {
    return <Navigate to="/" replace />;
  }

  return children;
};

export default ProtectedRoute;
