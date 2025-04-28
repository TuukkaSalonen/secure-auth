import { LOGIN, LOGOUT, SET_USER, SET_MFA } from "../constants";

// Auth state interface for authenticaton state management
export type AuthState = {
  isAuthenticated: boolean;
  user?: string | null;
  mfa_enabled?: boolean | null;
  loading?: boolean;
};

// Initial state for authentication
const initialState: AuthState = {
  isAuthenticated: false,
  user: null,
  mfa_enabled: null,
  loading: true,
};

// Auth action for reducer
interface AuthAction {
  type: string;
  payload?: string | boolean | null;
}

// Auth reducer for managing authentication state
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
