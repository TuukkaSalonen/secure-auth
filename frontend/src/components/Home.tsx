import React, { useState } from "react";
import { Link } from "react-router-dom";
import styles from "./styles/Home.module.css";
import { useDispatch, useSelector } from "react-redux";
import { RootState } from "../redux/store";
import { logOut, setupMFA, verifySetupMFA, disableMFA } from "../api/auth";
import { setMFA } from "../redux/authActions";

const Home: React.FC = () => {
  const isAuthenticated = useSelector(
    (state: RootState) => state.auth.isAuthenticated
  );
  const mfaEnabled = useSelector((state: RootState) => state.auth.mfa_enabled);
  const username = useSelector((state: RootState) => state.auth.user);
  const [openMfa, setOpenMfa] = useState(false);
  const [qrcode, setQrcode] = useState<string | null>(null);
  const [mfaCode, setMfaCode] = useState("");

  const dispatch = useDispatch();

  const handleLogOut = async () => {
    await logOut(dispatch);
  };

  const handleOpenMfa = async () => {
    setOpenMfa(true);
    const setupMfaSuccess = await setupMFA();
    if (setupMfaSuccess && setupMfaSuccess.success) {
      setQrcode(setupMfaSuccess.url || null);
    }
  };

  const handleCloseMfa = () => {
    setOpenMfa(false);
    setQrcode(null);
    setMfaCode("");
  };

  const handleMFASubmit = async () => {
    const verifyMfaSuccess = await verifySetupMFA(mfaCode);
    if (verifyMfaSuccess && verifyMfaSuccess.success) {
      dispatch(setMFA(true));
      setOpenMfa(false);
      setMfaCode("");
    }
  };

  const handleMFADisable = () => {
    setOpenMfa(true);
  };

  const handleMFADisableSubmit = async () => {
    const confirmDisable = window.confirm(
      "Are you sure you want to disable MFA? You can re-enable it later."
    );
    if (confirmDisable) {
      const disableMfaSuccess = await disableMFA(mfaCode);
      if (disableMfaSuccess && disableMfaSuccess.success) {
        dispatch(setMFA(false));
        setOpenMfa(false);
        setMfaCode("");
      }
    }
  };

  return (
    <div className={styles.homeContainer}>
      <h2>Welcome to the Secure Programming Application</h2>
      {isAuthenticated ? (
        <>
          <p>Hello, {username}</p>
          <Link to="/files">
            <button className={styles.btn}>Files</button>
          </Link>
          {mfaEnabled ? (
            <>
              <p>Multi-factor authentication is currently enabled.</p>
              {!openMfa ? (
                <button onClick={handleMFADisable} className={styles.btn}>
                  Disable MFA
                </button>
              ) : (
                <>
                  <div>
                    <p>Enter your MFA code to disable MFA:</p>
                    <input
                      type="number"
                      value={mfaCode}
                      onChange={(e) => setMfaCode(e.target.value)}
                    />
                    <button
                      onClick={handleMFADisableSubmit}
                      className={styles.btn}
                    >
                      Submit
                    </button>
                  </div>
                  <button onClick={handleCloseMfa} className={styles.btn}>
                    Cancel
                  </button>
                </>
              )}
            </>
          ) : (
            <div>
              <p>Multi Factor Authentication is not enabled</p>
              {!openMfa ? (
                <button onClick={handleOpenMfa} className={styles.btn}>
                  Enable MFA
                </button>
              ) : (
                <>
                  <div>
                    <p>Scan the QR code with your authenticator app:</p>
                    {qrcode && <img src={qrcode} alt="qrcode" />}
                    <input
                      type="number"
                      value={mfaCode}
                      onChange={(e) => setMfaCode(e.target.value)}
                    />
                    <button onClick={handleMFASubmit} className={styles.btn}>
                      Submit
                    </button>
                  </div>
                  <button onClick={handleCloseMfa} className={styles.btn}>
                    Cancel
                  </button>
                </>
              )}
            </div>
          )}
          <button onClick={handleLogOut} className={styles.btn}>
            Logout
          </button>
        </>
      ) : (
        <>
          <p>Log in or register to continue.</p>

          <div className={styles.buttonContainer}>
            <Link to="/login">
              <button className={styles.btn}>Login</button>
            </Link>
            <Link to="/register">
              <button className={styles.btn}>Register</button>
            </Link>
          </div>
        </>
      )}
    </div>
  );
};

export default Home;
