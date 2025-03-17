import { LOGIN, LOGOUT, SET_USER, SET_MFA } from "./constants";

export const login = (token: string) => ({
  type: LOGIN,
  payload: token,
});

export const logout = () => ({
  type: LOGOUT,
});

export const setUser = (user: string) => ({
  type: SET_USER,
  payload: user,
});

export const setMFA = (mfa: boolean) => ({
  type: SET_MFA,
  payload: mfa,
});