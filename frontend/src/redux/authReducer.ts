import { LOGIN, LOGOUT, SET_USER, SET_MFA } from "./constants";

type AuthState = {
  isAuthenticated: boolean;
  user?: string | null;
  mfa_enabled?: boolean | null;
  loading?: boolean;
};

const initialState: AuthState = {
  isAuthenticated: false,
  user: null,
  mfa_enabled: null,
  loading: true,
};

interface AuthAction {
  type: string;
  payload?: string | boolean | null;
}

const authReducer = (state = initialState, action: AuthAction): AuthState => {
  switch (action.type) {
    case LOGIN:
      return { ...state, isAuthenticated: true, loading: false };
    case LOGOUT:
      return {...initialState, loading: false};
    case SET_USER:
      return { ...state, user: typeof action.payload === 'string' ? action.payload : state.user };
    case SET_MFA:
      return { ...state, mfa_enabled: action.payload as boolean };
    default:
      return state;
  }
};

export default authReducer;
