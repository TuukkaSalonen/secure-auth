import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import styles from "./styles/Login.module.css";
import { useNavigate } from "react-router-dom";
import { postLogin, verifyLoginMFA, ProviderLogin } from "../api/auth";
import { useDispatch } from "react-redux";
import { validateLoginInput } from "../validators";
import { faGoogle, faGithub } from "@fortawesome/free-brands-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";

// Login component for user authentication
const Login: React.FC = () => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [errorMessage, setErrorMessage] = useState("");
  const [mfaRequired, setMfaRequired] = useState(false);
  const navigate = useNavigate();
  const dispatch = useDispatch();

  // Check if MFA is required on component mount (from OAuth redirect when MFA is enabled)
  useEffect(() => {
    const searchParams = new URLSearchParams(window.location.search);
    if (searchParams.has("mfa_required")) {
      setMfaRequired(true);
      navigate(window.location.pathname, { replace: true });
    }
  }, [navigate]);

  // Handle form submission for login
  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();

    // Validate input fields
    const validateInput = await validateLoginInput(username, password);
    if (validateInput.success === false) {
      setErrorMessage(validateInput.message);
      return;
    }
    setErrorMessage("");

    // Attempt to log in the user
    const loginResponse = await postLogin(username, password, dispatch);
    if (loginResponse && loginResponse.success) {
      handleHome();
    } else {
      // If MFA is required, set the state to show the MFA input field
      if (loginResponse.mfaRequired) {
        setMfaRequired(true);
        return;
      }
      setErrorMessage(loginResponse.message);
    }
  };

  // Handle form submission for MFA code verification
  const handleSubmitMFA = async (event: React.FormEvent) => {
    event.preventDefault();

    // Send the MFA code to the server for verification
    const loginResponse = await verifyLoginMFA(totp, dispatch);

    // Navigate to the home page if successful, otherwise show error message
    if (loginResponse && loginResponse.success) {
      navigate("/");
    } else {
      setErrorMessage(loginResponse.message);
      // If the MFA has expired, reset the state
      if (loginResponse && loginResponse.expired) {
        setMfaRequired(false);
      }
    }
  };

  // Handle cancel button click to reset state
  const handleCancel = async () => {
    setPassword("");
    setTotp("");
    setUsername("");
    setErrorMessage("");
    setMfaRequired(false);
  };

  // Handle navigation to home page
  const handleHome = async () => {
    navigate("/");
  };

  // Handle login with third-party providers (Google, GitHub) and redirect to OAuth flow
  const handleProviderLogin = async (provider: string) => {
    ProviderLogin(provider);
  };

  return (
    <div className={styles["login-container"]}>
      <h2 className={styles["h2"]}>Login</h2>
      {errorMessage && (
        <p className={styles["error-message"]}>{errorMessage}</p>
      )}
      {/* MFA required condition to display code field */}
      {mfaRequired ? (
        <div>
          <p>
            Multi-factor authentication is required. Please submit the code from
            the authenticator app.
          </p>
          <form className={styles["form"]} onSubmit={handleSubmitMFA}>
            <input
              type="number"
              placeholder="Your code"
              value={totp}
              onChange={(e) => setTotp(e.target.value)}
            />
            <button
              className={styles["submit-button"]}
              onClick={handleSubmitMFA}
            >
              Submit
            </button>
          </form>
          <button className={styles["submit-button"]} onClick={handleCancel}>
            Cancel
          </button>
        </div>
      ) : (
        <>
          <form onSubmit={handleSubmit}>
            <div className={styles["form-group"]}>
              <label>Username/Email:</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </div>
            <div className={styles["form-group"]}>
              <label>Password:</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
            <button type="submit" className={styles["submit-button"]}>
              Login
            </button>
          </form>
          <button className={styles["submit-button"]} onClick={handleHome}>
            Cancel
          </button>
          <p>Or login with:</p>
          <div className={styles["sso-container"]}>
            <button
              className={styles["sso-button"]}
              onClick={() => handleProviderLogin("google")}
            >
              <FontAwesomeIcon icon={faGoogle} className={styles["icon"]} />
            </button>
            <button
              className={styles["sso-button"]}
              onClick={() => handleProviderLogin("github")}
            >
              <FontAwesomeIcon icon={faGithub} className={styles["icon"]} />
            </button>
          </div>
        </>
      )}
      <Link to="/register">Don't have an account? Register here</Link>
    </div>
  );
};

export default Login;
