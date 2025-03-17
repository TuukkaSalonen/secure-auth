import { LOGIN, LOGOUT, SET_USER, SET_MFA } from "./constants";

type AuthState = {
  isAuthenticated: boolean;
  user?: string | null;
  mfa_enabled?: boolean;
};

const initialState: AuthState = {
  isAuthenticated: false,
  user: null,
  mfa_enabled: false,
};

interface AuthAction {
  type: string;
  payload?: string | boolean | null;
}

const authReducer = (state = initialState, action: AuthAction): AuthState => {
  switch (action.type) {
    case LOGIN:
      return { ...state, isAuthenticated: true };
    case LOGOUT:
      return { ...state, isAuthenticated: false, user: null };
    case SET_USER:
      return { ...state, user: typeof action.payload === 'string' ? action.payload : state.user };
    case SET_MFA:
      return { ...state, mfa_enabled: action.payload as boolean };
    default:
      return state;
  }
};

export default authReducer;
