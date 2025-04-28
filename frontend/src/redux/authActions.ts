import { LOGIN, LOGOUT, SET_USER, SET_MFA } from "../constants";

// Login action
export const login = () => ({
  type: LOGIN
});

// Logout action
export const logout = () => ({
  type: LOGOUT,
});

// Set user action
export const setUser = (user: string) => ({
  type: SET_USER,
  payload: user,
});

// Set MFA action
export const setMFA = (mfa: boolean) => ({
  type: SET_MFA,
  payload: mfa,
});