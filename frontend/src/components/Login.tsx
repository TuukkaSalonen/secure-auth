import React, { useState } from "react";
import { Link } from "react-router-dom";
import styles from "./styles/Login.module.css";
import { useNavigate } from "react-router-dom";
import { postLogin, verifyLoginMFA } from "../api/auth";
import { useDispatch } from "react-redux";
import { validateLoginInput } from "../validators";

const Login: React.FC = () => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [errorMessage, setErrorMessage] = useState("");
  const [mfaRequired, setMfaRequired] = useState(false);
  const navigate = useNavigate();
  const dispatch = useDispatch();

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    const validateInput = validateLoginInput(username, password);
    if (validateInput.success === false) {
      setErrorMessage(validateInput.message);
      return;
    }
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
    const loginResponse = await verifyLoginMFA(username, totp, dispatch);
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
              type="text"
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
          <button className={styles["submit-button"]} onClick={handleCancel}>Cancel</button>
        </div>
      ) : (
        <form onSubmit={handleSubmit}>
          <div>
            <label>Username:</label>
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
      )}
      <button className={styles["submit-button"]} onClick={handleHome}>Cancel</button>
      <Link to="/register">Don't have an account? Register here</Link>
    </div>
  );
};

export default Login;
