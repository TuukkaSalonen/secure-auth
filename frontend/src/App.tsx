import React, { useEffect } from "react";
import { BrowserRouter as Router, Route, Routes } from "react-router-dom";
import Login from "./components/Login";
import Register from "./components/Register";
import Home from "./components/Home";
import "./App.css";
import { checkLoggedIn, refreshToken } from "./api/auth";
import { useDispatch, useSelector } from "react-redux";
import { logout } from "./redux/authActions";
import { RootState, AppDispatch } from "./redux/store";
import Files from "./components/Files";
import ProtectedRoute from "./components/ProtectedRoute";
import { Authenticator } from "./components/Authenticator";
import UnauthenticatedRoute from "./components/UnauthenticatedRoute";

// Main App component
const App: React.FC = () => {
  const dispatch = useDispatch<AppDispatch>();
  const auth = useSelector((state: RootState) => state.auth);

  // Check if user is logged in on mount
  useEffect(() => {
    const loginCheck = async () => {
      const loggedIn =
        (await checkLoggedIn(dispatch)) || (await refreshToken(dispatch));
      if (!loggedIn) {
        dispatch(logout());
      }
    };
    loginCheck();
  }, [dispatch]);

  // If user is logged in, set up interval to refresh token
  useEffect(() => {
    if (!auth.isAuthenticated) return;
    const refreshInterval = setInterval(async () => {
      const loggedIn = await refreshToken(dispatch);
      if (!loggedIn) {
        clearInterval(refreshInterval);
        dispatch(logout());
      }
    }, 10 * 60 * 1000); // 10 minutes

    return () => {
      clearInterval(refreshInterval);
    };
  }, [dispatch, auth.isAuthenticated]);

  return (
    <Router>
      <div className="app-container">
        <Routes>
          <Route path="/" element={<Home />} />
          {/* Protect /files route from unauthenticated access */}
          <Route
            path="/files"
            element={
              <ProtectedRoute>
                <Files />
              </ProtectedRoute>
            }
          />
          {/* Protect /mfa route from unauthenticated access */}
          <Route
            path="/mfa"
            element={
              <ProtectedRoute>
                <Authenticator />
              </ProtectedRoute>
            }
          />
          {/* Limit /login route from authenticated users */}
          <Route
            path="/login"
            element={
              <UnauthenticatedRoute>
                <Login />
              </UnauthenticatedRoute>
            }
          />
          {/* Limit /register route from authenticated users */}
          <Route
            path="/register"
            element={
              <UnauthenticatedRoute>
                <Register />
              </UnauthenticatedRoute>
            }
          />
        </Routes>
      </div>
    </Router>
  );
};

export default App;
