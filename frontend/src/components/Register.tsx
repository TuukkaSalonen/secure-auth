import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import styles from "./styles/Register.module.css";
import { postRegister } from "../api/auth";
import { validateRegisterInput } from "../validators";
import { toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

// Register component for user registration
const Register: React.FC = () => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const navigate = useNavigate();

  // Handle form submission
  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();

    // Validate input fields
    const validateInput = await validateRegisterInput(
      username,
      password,
      confirmPassword
    );
    if (validateInput.success === false) {
      toast.error(validateInput.message);
      return;
    }
    if (password !== confirmPassword) {
      toast.error("Passwords do not match");
      return;
    }
    const registerSuccess = await postRegister(username, password);

    // Check if registration was successful and navigate to login page
    if (registerSuccess && registerSuccess.success) {
      toast.success("Registration successful! Please log in.");
      navigate("/login");
    } else {
      toast.error(registerSuccess.message);
    }
  };

  // Navigate to home page
  const handleHome = async () => {
    navigate("/");
  };

  return (
    <div className={styles["register-container"]}>
      <h2>Register</h2>
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
      <Link to="/login">Login with existing account, Google or GitHub</Link>
    </div>
  );
};

export default Register;
