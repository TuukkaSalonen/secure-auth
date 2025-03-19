import { login, logout, setUser, setMFA } from "../redux/authActions";
import { AppDispatch } from "../redux/store";

export const getCSRFRefreshToken = async () => {
  return document.cookie
    .split("; ")
    .find((row) => row.startsWith("csrf_refresh_token="))
    ?.split("=")[1];
};

export const getCSRFAccessToken = async () => {
  return document.cookie
    .split("; ")
    .find((row) => row.startsWith("csrf_access_token="))
    ?.split("=")[1];
};

export const checkLoggedIn = async (dispatch: AppDispatch) => {
  try {
    const response = await fetch("http://localhost:5000/api/check", {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
    });

    if (response.ok) {
      const data = await response.json();
      dispatch(login(data.access_token));
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

export const refreshToken = async (dispatch: AppDispatch) => {
  try {
    const csrfToken = await getCSRFRefreshToken();
    const response = await fetch("http://localhost:5000/api/refresh", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(csrfToken && { "X-CSRF-Token": csrfToken }),
      },
      credentials: "include",
    });

    if (response.ok) {
      const data = await response.json();
      dispatch(login(data.access_token));
      dispatch(setUser(data.user));
      return true;
    }
    return false;
  } catch (error) {
    console.error("Error refreshing token:", error);
    return false;
  }
};

export const logOut = async (dispatch: AppDispatch) => {
  try {
    const csrfToken = await getCSRFAccessToken();
    await fetch("http://localhost:5000/api/logout", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(csrfToken && { "X-CSRF-Token": csrfToken }),
      },
      credentials: "include",
    });
    dispatch(logout());
  } catch (error) {
    console.error("Error logging out:", error);
    dispatch(logout()); // Log out locally even if server request fails
  }
};

export const postRegister = async (username: string, password: string) => {
  try {
    const response = await fetch("http://localhost:5000/api/register", {
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

export const postLogin = async (
  username: string,
  password: string,
  dispatch: AppDispatch
) => {
  try {
    const response = await fetch("http://localhost:5000/api/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
      body: JSON.stringify({ username, password }),
    });
    const data = await response.json();
    if (response.ok) {
      dispatch(login(data.access_token));
      dispatch(setUser(data.user));
      return { success: true, message: data.message };
    }
    if (data.mfa_required) {
      return { success: false, mfaRequired: true, message: data.message };
    }
    return { success: false, message: data.message };
  } catch (error) {
    console.error("Login failed:", error);
    return { success: false, message: "Login failed" };
  }
};

export const verifyLoginMFA = async (
  username: string,
  totpCode: string,
  dispatch: AppDispatch
) => {
  try {
    const csrfToken = await getCSRFAccessToken();
    const response = await fetch("http://localhost:5000/api/login/verify", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(csrfToken && { "X-CSRF-Token": csrfToken }),
      },
      credentials: "include",
      body: JSON.stringify({ username, totp_code: totpCode }),
    });
    const data = await response.json();
    if (response.ok) {
      dispatch(login(data.access_token));
      dispatch(setUser(data.user));
      dispatch(setMFA(data.mfa_enabled));
      return { success: true, message: "MFA Verified" };
    }
    return { success: false, message: data.message };
  } catch (error) {
    console.error("MFA verification failed:", error);
    return { success: false, message: "MFA verification failed" };
  }
};

export const setupMFA = async () => {
  try {
    const csrfToken = await getCSRFAccessToken();
    const response = await fetch("http://localhost:5000/api/mfa/setup", {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
        ...(csrfToken && { "X-CSRF-Token": csrfToken }),
      },
      credentials: "include",
    });
    const image = await response.blob();
    if (response.ok) {
      const url = URL.createObjectURL(image);
      return { success: true, url };
    }
    return { success: false, message: "MFA setup failed" };
  } catch (error) {
    console.error("MFA setup failed:", error);
    return { success: false, message: "MFA setup failed" };
  }
};

export const verifySetupMFA = async (code: string) => {
  try {
    const csrfToken = await getCSRFAccessToken();
    const response = await fetch("http://localhost:5000/api/mfa/setup/verify", {
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
