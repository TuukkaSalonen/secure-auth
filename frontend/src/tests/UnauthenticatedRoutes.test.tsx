import { configureStore } from "@reduxjs/toolkit";
import { Provider } from "react-redux";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import UnauthenticatedRoute from "../components/UnauthenticatedRoute";
import Home from "../components/Home";
import authReducer, { AuthState } from "../redux/authReducer";
import Login from "../components/Login";
import Register from "../components/Register";
import '@testing-library/jest-dom';

// Test cases for unprotected routes (not logged in)

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
            path="/login"
            element={
              <UnauthenticatedRoute>
                <Login />
              </UnauthenticatedRoute>
            }
          />
          <Route
            path="/register"
            element={
              <UnauthenticatedRoute>
                <Register />
              </UnauthenticatedRoute>
            }
          />
          <Route path="/" element={<Home />} />
        </Routes>
      </MemoryRouter>
    </Provider>
  );
};

// Test that user is redirected to home when accessing register route when authenticated
test("redirects to home when logged in user accessing register route", async () => {
  const unauthenticatedState: AuthState = {
    isAuthenticated: true,
    loading: false,
    user: "SecureUser",
  };

  renderWithAuthState(unauthenticatedState, "/register");

  await waitFor(() => {
    // Check that the user is redirected to the home page
    expect(
      screen.getByText(/welcome to the secure programming application/i)
    ).toBeInTheDocument();

    // Check that correct elements are rendered
    expect(screen.queryByText(/hello, secureuser/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /mfa setup/i })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /files/i })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /logout/i })).toBeInTheDocument();

    expect(screen.queryByRole("button", { name: /Login/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Register/i })).not.toBeInTheDocument();
  });
});

// Test that user is redirected to home when accessing register route when authenticated
test("redirects to home when logged in user accessing login route", async () => {
    const unauthenticatedState: AuthState = {
      isAuthenticated: true,
      loading: false,
      user: "SecureUser",
    };
  
    renderWithAuthState(unauthenticatedState, "/login");
  
    await waitFor(() => {
      // Check that the user is redirected to the home page
      expect(
        screen.getByText(/welcome to the secure programming application/i)
      ).toBeInTheDocument();
      
      // Check that correct elements are rendered
      expect(screen.queryByText(/hello, secureuser/i)).toBeInTheDocument();
      expect(screen.queryByRole("button", { name: /mfa setup/i })).toBeInTheDocument();
      expect(screen.queryByRole("button", { name: /files/i })).toBeInTheDocument();
      expect(screen.queryByRole("button", { name: /logout/i })).toBeInTheDocument();
  
      expect(screen.queryByRole("button", { name: /Login/i })).not.toBeInTheDocument();
      expect(screen.queryByRole("button", { name: /Register/i })).not.toBeInTheDocument();
    });
  });