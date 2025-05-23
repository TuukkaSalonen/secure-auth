import { configureStore } from "@reduxjs/toolkit";
import { Provider } from "react-redux";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import Home from "../components/Home";
import authReducer from "../redux/authReducer";
import '@testing-library/jest-dom'

// Test cases for username rendering using name that includes different HTML tags

// Test that alert is not executed
test("renders username safely", () => {
  const store = configureStore({
    reducer: {
      auth: authReducer,
    },
    preloadedState: {
      auth: {
        isAuthenticated: true,
        loading: false,
        user: '<script>alert("XSS")</script>',
      },
    },
  });

  render(
    <Provider store={store}>
      <MemoryRouter>
        <Home />
      </MemoryRouter>
    </Provider>
  );

  // Check that the alert is not executed
  expect(screen.queryByText('alert("XSS")')).not.toBeInTheDocument();
  expect(
    screen.getByText('Hello, <script>alert("XSS")</script>')
  ).toBeInTheDocument();
});

// Test that bold is not rendered as HTML
test("renders HTML tags in username as plain text", () => {
  const store = configureStore({
    reducer: { auth: authReducer },
    preloadedState: {
      auth: {
        isAuthenticated: true,
        loading: false,
        user: "<b>BoldUser</b>",
      },
    },
  });

  render(
    <Provider store={store}>
      <MemoryRouter>
        <Home />
      </MemoryRouter>
    </Provider>
  );

  // Check that it is rendered as string, not bold
  expect(screen.getByText("Hello, <b>BoldUser</b>")).toBeInTheDocument();
});

// Test that SVG is not executed on load
test("does not execute SVG onload XSS", () => {
  const store = configureStore({
    reducer: { auth: authReducer },
    preloadedState: {
      auth: {
        isAuthenticated: true,
        loading: false,
        user: '<svg onload=alert("XSS")></svg>',
      },
    },
  });

  render(
    <Provider store={store}>
      <MemoryRouter>
        <Home />
      </MemoryRouter>
    </Provider>
  );

  // Check that alert is not executed
  expect(screen.queryByText('alert("XSS")')).not.toBeInTheDocument();
  expect(
    screen.getByText('Hello, <svg onload=alert("XSS")></svg>')
  ).toBeInTheDocument();
});

// Test that image onerror is not executed
test("does not execute image onerror XSS", () => {
  const store = configureStore({
    reducer: { auth: authReducer },
    preloadedState: {
      auth: {
        isAuthenticated: true,
        loading: false,
        user: "<img src=x onerror=alert(1)>",
      },
    },
  });

  render(
    <Provider store={store}>
      <MemoryRouter>
        <Home />
      </MemoryRouter>
    </Provider>
  );

  // Check that alert to not executed
  expect(screen.queryByText("alert(1)")).not.toBeInTheDocument();
  expect(
    screen.getByText("Hello, <img src=x onerror=alert(1)>")
  ).toBeInTheDocument();
});
