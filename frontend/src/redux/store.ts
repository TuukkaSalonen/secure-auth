import { configureStore } from '@reduxjs/toolkit';
import authReducer from './authReducer';

export type AppDispatch = typeof store.dispatch;
export type RootState = ReturnType<typeof store.getState>;

const store = configureStore({
  reducer: {
    auth: authReducer,
  },
});

export default store;

