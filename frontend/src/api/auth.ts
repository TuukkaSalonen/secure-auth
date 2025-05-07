import { login, logout, setUser, setMFA } from "../redux/authActions";
import { AppDispatch } from "../redux/store";
import { fetchWrapper } from "./fetchWrapper";
import { API_BASE_URL } from "../constants";

// Authentication API calls
// CSRF tokens are sent with requests where applicable

// Get CSRF refresh token from cookie
export const getCSRFRefreshToken = async () => {
  return document.cookie
    .split("; ")
    .find((row) => row.startsWith("csrf_refresh_token="))
    ?.split("=")[1];
};

// Get CSRF access token from cookie
export const getCSRFAccessToken = async () => {
  return document.cookie
    .split("; ")
    .find((row) => row.startsWith("csrf_access_token="))
    ?.split("=")[1];
};

// API call to check if user is logged in
// Does not require CSRF token as can be called without authentication
export const checkLoggedIn = async (dispatch: AppDispatch) => {
  try {
    const response = await fetchWrapper(`${API_BASE_URL}/check`, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
    });
    if (response.ok) {
      const data = await response.json();
      dispatch(login());
      dispatch(setUser(data.user));
      dispatch(setMFA(data.mfa_enabled));
      return true;
    }
    return false;
  } catch (error) {
    console.error("Error checking if user is logged in:", error);
    return false;
  }
};

// API call to refresh access token
export const refreshToken = async (dispatch: AppDispatch) => {
  try {
    const csrfToken = await getCSRFRefreshToken();
    const response = await fetchWrapper(`${API_BASE_URL}/refresh`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(csrfToken && { "X-CSRF-Token": csrfToken }),
      },
      credentials: "include",
    });

    if (response.ok) {
      const data = await response.json();
      dispatch(login());
      dispatch(setUser(data.user));
      return true;
    }
    return false;
  } catch (error) {
    console.error("Error refreshing token:", error);
    return false;
  }
};

// API call to log out
export const logOut = async (dispatch: AppDispatch) => {
  try {
    const csrfToken = await getCSRFAccessToken();
    await fetchWrapper(`${API_BASE_URL}/logout`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(csrfToken && { "X-CSRF-Token": csrfToken }),
      },
      credentials: "include",
    });
    dispatch(logout());
    return true;
  } catch (error) {
    console.error("Error logging out:", error);
    dispatch(logout()); // Log out locally even if server request fails
    return false;
  }
};

// API call to register new user
export const postRegister = async (username: string, password: string) => {
  try {
    const response = await fetchWrapper(`${API_BASE_URL}/register`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ username, password }),
    });
    const data = await response.json();
    if (response.ok) {
      return { success: true, message: data.message };
    }
    return { success: false, message: data.message };
  } catch (error) {
    console.error("Registration failed:", error);
    return { success: false, message: "Registration failed" };
  }
};

// API call to log in
export const postLogin = async (
  username: string,
  password: string,
  dispatch: AppDispatch
) => {
  try {
    const response = await fetchWrapper(`${API_BASE_URL}/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
      body: JSON.stringify({ username, password }),
    });
    const data = await response.json();

    // If login is successful, set user and MFA state
    if (response.ok) {
      dispatch(login());
      dispatch(setUser(data.user));
      return { success: true, message: data.message };
    }
    // If MFA is required, set MFA state and return message
    if (data.mfa_required) {
      return { success: false, mfaRequired: true, message: data.message };
    }
    // If login fails, return error message
    return { success: false, message: data.message };
  } catch (error) {
    console.error("Login failed:", error);
    return { success: false, message: "Login failed" };
  }
};

// API call to verify MFA code during login
// This is called after the user has entered their username and password and MFA is required
// Also CSRF token is needed
export const verifyLoginMFA = async (
  totpCode: string,
  dispatch: AppDispatch
) => {
  try {
    const csrfToken = await getCSRFAccessToken();
    const response = await fetchWrapper(`${API_BASE_URL}/login/verify`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(csrfToken && { "X-CSRF-Token": csrfToken }),
      },
      credentials: "include",
      body: JSON.stringify({ totp_code: totpCode }),
    });
    const data = await response.json();
    // If MFA verification is successful, set user and MFA state
    if (response.ok) {
      dispatch(login());
      dispatch(setUser(data.user));
      dispatch(setMFA(data.mfa_enabled));
      return { success: true, message: "MFA Verified" };
    }
    // If server returns 401, it means the authentication process has expired
    else if (response.status === 401) {
      return {
        success: false,
        message: "Authentication process expired. Please login again.",
        expired: true,
      };
    }
    // If MFA verification fails, return error message
    return { success: false, message: data.message };
  } catch (error) {
    console.error("MFA verification failed:", error);
    return { success: false, message: "MFA verification failed" };
  }
};

// API call to set up MFA
export const setupMFA = async () => {
  try {
    const csrfToken = await getCSRFAccessToken();
    const response = await fetchWrapper(`${API_BASE_URL}/mfa/setup`, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
        ...(csrfToken && { "X-CSRF-Token": csrfToken }),
      },
      credentials: "include",
    });
    const image = await response.blob();
    // If the response is ok, create a URL for the image and return it
    if (response.ok) {
      const url = URL.createObjectURL(image);
      return { success: true, url };
    }
    const data = await response.json();
    if (data.message) {
      return { success: false, message: data.message };
    }
    return { success: false, message: "MFA setup failed" };
  } catch (error) {
    console.error("MFA setup failed:", error);
    return { success: false, message: "MFA setup failed" };
  }
};

// API call to verify MFA setup
export const verifySetupMFA = async (code: string) => {
  try {
    const csrfToken = await getCSRFAccessToken();
    const response = await fetchWrapper(`${API_BASE_URL}/mfa/setup/verify`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(csrfToken && { "X-CSRF-Token": csrfToken }),
      },
      credentials: "include",
      body: JSON.stringify({ totp_code: code }),
    });
    const data = await response.json();
    if (response.ok) {
      return { success: true, message: data.message };
    }
    return { success: false, message: data.message };
  } catch (error) {
    console.error("MFA verification failed:", error);
    return { success: false, message: "MFA verification failed" };
  }
};

// API call to disable MFA
export const disableMFA = async (code: string) => {
  try {
    const csrfToken = await getCSRFAccessToken();
    const response = await fetchWrapper(`${API_BASE_URL}/mfa/disable`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(csrfToken && { "X-CSRF-Token": csrfToken }),
      },
      credentials: "include",
      body: JSON.stringify({ totp_code: code }),
    });
    const data = await response.json();
    if (response.ok) {
      return { success: true, message: data.message };
    }
    return { success: false, message: data.message };
  } catch (error) {
    console.error("MFA disable failed:", error);
    return { success: false, message: "MFA disable failed" };
  }
};

// Google and GitHub login redirect
export const ProviderLogin = async (provider: string) => {
  window.location.href = `${API_BASE_URL}/login/${provider}`;
};
