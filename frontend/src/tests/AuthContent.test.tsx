import { configureStore } from "@reduxjs/toolkit";
import { Provider } from "react-redux";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import Home from "../components/Home";
import { Authenticator } from "../components/Authenticator";
import authReducer from "../redux/authReducer";
import { AuthState } from "../redux/authReducer";
import "@testing-library/jest-dom";

// Test cases for content rendering based on authentication state

// Component render
const renderWithAuthState = (authState: AuthState) => {
  const store = configureStore({
    reducer: { auth: authReducer },
    preloadedState: { auth: authState },
  });

  render(
    <Provider store={store}>
      <MemoryRouter>
        <Home />
        <Authenticator />
      </MemoryRouter>
    </Provider>
  );
};

// Test content rendering for unauthenticated users in Home component
test("renders login/register for unauthenticated users", () => {
  renderWithAuthState({
    isAuthenticated: false,
    loading: false,
    user: null,
  });

  // Check that login/register buttons are rendered
  expect(screen.getByRole("button", { name: /login/i })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /register/i })).toBeInTheDocument();

  // Check that username and other buttons are not rendered
  expect(screen.queryByText(/hello,/i)).not.toBeInTheDocument();
  expect(screen.queryByText(/mfa setup/i)).not.toBeInTheDocument();
  expect(screen.queryByText(/files/i)).not.toBeInTheDocument();
  expect(screen.queryByText(/logout/i)).not.toBeInTheDocument();
});

// Test content rendering for authenticated users in Home component
test("renders main content for authenticated users", () => {
  renderWithAuthState({
    isAuthenticated: true,
    loading: false,
    user: "SecureUser",
  });

  // Check that username and buttins are rendered
  expect(screen.getByText(/hello, secureuser/i)).toBeInTheDocument();
  expect(screen.getByText(/mfa setup/i)).toBeInTheDocument();
  expect(screen.getByText(/files/i)).toBeInTheDocument();
  expect(screen.getByText(/logout/i)).toBeInTheDocument();

  // Check that login/register buttons are not rendered
  expect(screen.queryByText(/login/i)).not.toBeInTheDocument();
  expect(screen.queryByText(/register/i)).not.toBeInTheDocument();
});

// Test content rendering for users with MFA enabled in Authenticator component
test("renders authenticator state for user with MFA enabled", () => {
  renderWithAuthState({
    isAuthenticated: true,
    loading: false,
    user: "SecureUser",
    mfa_enabled: true,
  });

  // Check that MFA status and buttons are displayed correctly
  expect(
    screen.getByText(/Multi-Factor authentication is currently enabled/i)
  ).toBeInTheDocument();

  expect(
    screen.getByRole("button", { name: /disable mfa/i })
  ).toBeInTheDocument();

  expect(
    screen.queryByText(/Multi-Factor authentication is currently not enabled/i)
  ).not.toBeInTheDocument();

  expect(
    screen.queryByRole("button", { name: /enable mfa/i })
  ).not.toBeInTheDocument();
});

// Test content rendering for users with MFA disabled in Authenticator component
test("renders authenticator state for user with MFA disabled", () => {
  renderWithAuthState({
    isAuthenticated: true,
    loading: false,
    mfa_enabled: false,
  });

  // Check that MFA status and buttons are displayed correctly
  expect(
    screen.getByText(/Multi-Factor authentication is currently not enabled/i)
  ).toBeInTheDocument();

  expect(
    screen.getByRole("button", { name: /enable mfa/i })
  ).toBeInTheDocument();

  expect(
    screen.queryByRole("button", { name: /disable mfa/i })
  ).not.toBeInTheDocument();
  
  expect(
    screen.queryByText(/Multi-Factor authentication is currently enabled/i)
  ).not.toBeInTheDocument();
});
