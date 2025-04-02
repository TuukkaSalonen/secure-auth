// src/App.tsx
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
  }
  , [dispatch]);

  // If user is logged in, set up interval to refresh token
  useEffect(() => {
    if (!auth.isAuthenticated) return;
      const refreshInterval = setInterval(async () => {
        const loggedIn = await refreshToken(dispatch);
        if (!loggedIn) {
          clearInterval(refreshInterval);
          dispatch(logout());
        }
      }, 14 * 60 * 1000); // 14 minutes

      return () => {
        clearInterval(refreshInterval);
      };
    }, [dispatch, auth.isAuthenticated]);

  return (
    <Router>
      <div className="app-container">
        <Routes>
          <Route path="/" element={<Home />} />
          {auth.user ? (
            <>
              <Route path="/login" element={<Login />} />
              <Route path="/register" element={<Register />} />
            </>
          ) : (
            <>
              <Route path="/login" element={<Login />} />
              <Route path="/register" element={<Register />} />
            </>
          )}
        </Routes>
      </div>
    </Router>
  );
};

export default App;
