import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import styles from "./styles/Login.module.css";
import { useNavigate } from "react-router-dom";
import { postLogin, verifyLoginMFA } from "../api/auth";
import { useDispatch } from "react-redux";
import { validateLoginInput } from "../validators";
import { faGoogle, faGithub } from "@fortawesome/free-brands-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";

const Login: React.FC = () => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [errorMessage, setErrorMessage] = useState("");
  const [mfaRequired, setMfaRequired] = useState(false);
  const navigate = useNavigate();
  const dispatch = useDispatch();

  useEffect(() => {
    const searchParams = new URLSearchParams(window.location.search);
    if (searchParams.has("mfa_required")) {
      setMfaRequired(true);
      navigate(window.location.pathname, { replace: true });
    }
  }, [navigate]);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    const validateInput = await validateLoginInput(username, password);
    if (validateInput.success === false) {
      setErrorMessage(validateInput.message);
      return;
    }
    setErrorMessage("");
    const loginResponse = await postLogin(username, password, dispatch);
    if (loginResponse && loginResponse.success) {
      navigate("/");
    } else {
      if (loginResponse.mfaRequired) {
        setMfaRequired(true);
        return;
      }
      setErrorMessage(loginResponse.message);
    }
  };

  const handleSubmitMFA = async (event: React.FormEvent) => {
    event.preventDefault();
    const loginResponse = await verifyLoginMFA(totp, dispatch);
    if (loginResponse && loginResponse.success) {
      navigate("/");
    } else {
      setErrorMessage(loginResponse.message);
    }
  };

  const handleCancel = async () => {
    setPassword("");
    setTotp("");
    setUsername("");
    setErrorMessage("");
    setMfaRequired(false);
  };

  const handleHome = async () => {
    navigate("/");
  };

  const handleSSOLogin = async (provider: string) => {
    window.location.href = `http://localhost:5000/api/login/${provider}`;
  };

  return (
    <div className={styles["login-container"]}>
      <h2 className={styles["h2"]}>Login</h2>
      {errorMessage && (
        <p className={styles["error-message"]}>{errorMessage}</p>
      )}
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
            <div>
              <label>Username/Email:</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </div>
            <div>
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
              onClick={() => handleSSOLogin("google")}
            >
              <FontAwesomeIcon icon={faGoogle} className={styles["icon"]} />
            </button>
            <button
              className={styles["sso-button"]}
              onClick={() => handleSSOLogin("github")}
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
