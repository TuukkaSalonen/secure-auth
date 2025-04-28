import { useDispatch, useSelector } from "react-redux";
import { RootState } from "../redux/store";
import { useState } from "react";
import { setupMFA, verifySetupMFA, disableMFA } from "../api/auth";
import { setMFA } from "../redux/authActions";
import styles from "./styles/Authenticator.module.css";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faSpinner } from "@fortawesome/free-solid-svg-icons/faSpinner";
import { Link } from "react-router-dom";

// Authenticator component for managing Multi-Factor Authentication (MFA)
export const Authenticator: React.FC = () => {
  const loading = useSelector((state: RootState) => state.auth.loading);
  const mfaEnabled = useSelector((state: RootState) => state.auth.mfa_enabled);
  const [openMfa, setOpenMfa] = useState(false);
  const [qrcode, setQrcode] = useState<string | null>(null);
  const [mfaCode, setMfaCode] = useState("");

  const dispatch = useDispatch();

  // Handle opening the MFA setup and generating the QR code
  const handleOpenMfa = async () => {
    setOpenMfa(true);
    const setupMfaSuccess = await setupMFA();
    if (setupMfaSuccess && setupMfaSuccess.success) {
      setQrcode(setupMfaSuccess.url || null);
    }
  };

  // Handle closing the MFA setup and resetting the state
  const handleCloseMfa = () => {
    setOpenMfa(false);
    setQrcode(null);
    setMfaCode("");
  };

  // Handle submitting the MFA code for verification
  const handleMFASubmit = async () => {
    const verifyMfaSuccess = await verifySetupMFA(mfaCode);
    if (verifyMfaSuccess && verifyMfaSuccess.success) {
      dispatch(setMFA(true));
      setOpenMfa(false);
      setMfaCode("");
    }
  };

  // Handle disabling MFA and resetting the state
  const handleMFADisable = () => {
    setOpenMfa(true);
  };

  // Handle submitting the MFA code to disable MFA
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
    <div className={styles.AuthenticatorContainer}>
      {loading ? (
        <>
          <h2>Welcome to the Secure Programming Application</h2>
          <div className={styles.loadingContainer}>
            <FontAwesomeIcon icon={faSpinner} spin size="2x" />
          </div>
        </>
      ) : (
        <>
          <h1>Multi-Factor Authentication</h1>
          {/* Display option to disable MFA if enabled */}
          {mfaEnabled ? (
            <>
              <p>Multi-Factor authentication is currently enabled.</p>
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
            <>
              {/* Else display option to enable MFA */}
              <p>Multi-Factor authentication is currently not enabled</p>
              {!openMfa ? (
                <button onClick={handleOpenMfa} className={styles.btn}>
                  Enable MFA
                </button>
              ) : (
                <>
                  <div className={styles.qrCodeContainer}>
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
            </>
          )}
          <Link to="/" className={styles.link}>
            Back to Home
          </Link>
        </>
      )}
    </div>
  );
};
