import { configureStore } from '@reduxjs/toolkit';
import authReducer from './authReducer';

export type AppDispatch = typeof store.dispatch;
export type RootState = ReturnType<typeof store.getState>;

// Redux store for application state management
const store = configureStore({
  reducer: {
    auth: authReducer,
  },
});

export default store;

