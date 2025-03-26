import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import styles from "./styles/Register.module.css";
import { postRegister } from "../api/auth";
import { validateRegisterInput } from "../validators";

const Register: React.FC = () => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [errorMessage, setErrorMessage] = useState("");
  const navigate = useNavigate();

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    const validateInput = await validateRegisterInput(username, password, confirmPassword);
    if (validateInput.success === false) {
      setErrorMessage(validateInput.message);
      return;
    }
    if (password !== confirmPassword) {
      setErrorMessage("Passwords do not match");
      return;
    }
    const registerSuccess = await postRegister(username, password);
    if (registerSuccess && registerSuccess.success) {
      navigate("/login");
    } else {
      setErrorMessage(registerSuccess.message);
    }
  };

  const handleHome = async () => {
    navigate("/");
  };

  return (
    <div className={styles["register-container"]}>
      <h2>Register</h2>
      {errorMessage && (
        <p className={styles["error-message"]}>{errorMessage}</p>
      )}
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
        <div className={styles["form-group"]}>
          <label>Confirm Password:</label>
          <input
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
          />
        </div>
        <button type="submit">Register</button>
      </form>
      <button onClick={handleHome}>Cancel</button>
      <Link to="/login">Already have an account? Login here</Link>
    </div>
  );
};

export default Register;
