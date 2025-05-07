import { configureStore } from "@reduxjs/toolkit";
import { Provider } from "react-redux";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import ProtectedRoute from "../components/ProtectedRoute";
import Files from "../components/Files";
import Home from "../components/Home";
import authReducer, { AuthState } from "../redux/authReducer";
import { Authenticator } from "../components/Authenticator";
import '@testing-library/jest-dom';

// Test cases for protected routes

// Component render
const renderWithAuthState = (authState: AuthState, initialRoute: string) => {
  const store = configureStore({
    reducer: { auth: authReducer },
    preloadedState: { auth: authState },
  });

  render(
    <Provider store={store}>
      <MemoryRouter initialEntries={[initialRoute]}>
        <Routes>
          <Route
            path="/files"
            element={
              <ProtectedRoute>
                <Files />
              </ProtectedRoute>
            }
          />
          <Route
            path="/mfa"
            element={
              <ProtectedRoute>
                <Authenticator />
              </ProtectedRoute>
            }
          />
          <Route path="/" element={<Home />} />
        </Routes>
      </MemoryRouter>
    </Provider>
  );
};

// Test that user is redirected to home when accessing files route without authentication
test("redirects to home when accessing files route without authentication", async () => {
  const unauthenticatedState: AuthState = {
    isAuthenticated: false,
    loading: false,
    user: null,
  };

  renderWithAuthState(unauthenticatedState, "/files");

  await waitFor(() => {
    // Check that the user is redirected to the home page
    expect(
      screen.getByText(/welcome to the secure programming application/i)
    ).toBeInTheDocument();

    expect(screen.queryByRole("button", { name: /Login/i })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Register/i })).toBeInTheDocument();
  });
});

// Test that user is redirected to home when accessing authenticator route without authentication
test("redirects to home when accessing authenticator route without authentication", async () => {
    const unauthenticatedState: AuthState = {
      isAuthenticated: false,
      loading: false,
      user: null,
    };
  
    renderWithAuthState(unauthenticatedState, "/mfa");
  
    await waitFor(() => {
    // Check that the user is redirected to the home page
      expect(
        screen.getByText(/welcome to the secure programming application/i)
      ).toBeInTheDocument();

      expect(screen.queryByRole("button", { name: /Login/i })).toBeInTheDocument();
      expect(screen.queryByRole("button", { name: /Register/i })).toBeInTheDocument();
    });
  });