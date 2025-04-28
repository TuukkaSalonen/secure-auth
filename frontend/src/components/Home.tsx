import React from "react";
import { Link } from "react-router-dom";
import styles from "./styles/Home.module.css";
import { useDispatch, useSelector } from "react-redux";
import { RootState } from "../redux/store";
import { logOut } from "../api/auth";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faSpinner } from "@fortawesome/free-solid-svg-icons";

// Home component for the application
const Home: React.FC = () => {
  const isAuthenticated = useSelector(
    (state: RootState) => state.auth.isAuthenticated
  );
  const loading = useSelector((state: RootState) => state.auth.loading);
  const username = useSelector((state: RootState) => state.auth.user);

  const dispatch = useDispatch();

  // Handle user logout
  const handleLogOut = async () => {
    await logOut(dispatch);
  };

  return (
    <div className={styles.homeContainer}>
      {/* Display loading spinner while checking authentication status */}
      {loading ? (
        <>
          <h2>Welcome to the Secure Programming Application</h2>
          <div className={styles.loadingContainer}>
            <FontAwesomeIcon icon={faSpinner} spin size="2x" />
          </div>
        </>
      ) : (
        <>
          <h2>Welcome to the Secure Programming Application</h2>
          {/* Display buttons to files and mfa setup for logged in users */}
          {isAuthenticated ? (
            <>
              <p>Hello, {username}</p>
              <Link to="/mfa">
                <button className={styles.homeLink}>MFA setup</button>
              </Link>

              <Link to="/files">
                <button className={styles.homeLink}>Files</button>
              </Link>
              <button onClick={handleLogOut} className={styles.homeBtn}>
                Logout
              </button>
            </>
          ) : (
            <>
              {/* Display login and register buttons for unauthenticated users */}
              <p>Log in or register to continue.</p>
              <div className={styles.buttonContainer}>
                <Link to="/login">
                  <button className={styles.homeLink}>Login</button>
                </Link>
                <Link to="/register">
                  <button className={styles.homeLink}>Register</button>
                </Link>
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
};

export default Home;
