import { useState } from "react";
import type { FC, ChangeEvent, FormEvent } from "react";
import { useNavigate, Link } from "react-router-dom";
<<<<<<< Updated upstream
import { registerApi } from "../api/api";
=======
import { storeEncryptedPrivateKey } from "../api/api";
import { encryptPrivateKeyWithPassword, generateUserKeyPair, storeUserKeyPair } from "../utils/crypto";
import { useAuth } from "../context/AuthContext";
>>>>>>> Stashed changes
import "../styles/auth.css";

const Register: FC = (): JSX.Element => {
  const navigate = useNavigate();
  const { signupWithEmail } = useAuth();

  const [username, setUsername] = useState<string>("");
  const [email, setEmail] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const [confirmPassword, setConfirmPassword] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string>("");

  const handleRegister = async (e: FormEvent<HTMLFormElement>): Promise<void> => {
    e.preventDefault();
    setError("");

    if (!username.trim() || !email.trim() || !password.trim()) {
      setError("All fields are required");
      return;
    }

    if (password !== confirmPassword) {
      setError("Passwords do not match");
      return;
    }

    if (password.length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }

    setLoading(true);
    try {
      await signupWithEmail(email.trim(), password, username.trim());
      sessionStorage.setItem("tempPassword", password);

<<<<<<< Updated upstream
      if (loginData.success && loginData.accessToken) {
        // Store tokens and user info, then redirect to chat
        localStorage.setItem("accessToken", loginData.accessToken);
        localStorage.setItem("refreshToken", loginData.refreshToken);
        localStorage.setItem("user", JSON.stringify(loginData.user));
        navigate("/chat");
      } else {
        setError((data as { message?: string }).message || "User already exists");
=======
      // Keep the existing E2EE bootstrap flow unchanged.
      try {
        const keyPair = await generateUserKeyPair();
        await storeUserKeyPair(keyPair);
        const encryptedKeyData = await encryptPrivateKeyWithPassword(keyPair.privateKey, password);
        await storeEncryptedPrivateKey(encryptedKeyData);
      } catch (e2eeError) {
        console.error("Warning: failed to initialize encrypted private key storage:", e2eeError);
>>>>>>> Stashed changes
      }

      navigate("/chat");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to create account");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="auth-header">
          <h2>Create Account</h2>
          <p>Sign up with Firebase Email Authentication</p>
        </div>

        <form onSubmit={handleRegister} className="auth-form">
          <div className="form-group">
            <input
              type="text"
              placeholder="Display name"
              value={username}
              onChange={(e: ChangeEvent<HTMLInputElement>): void => setUsername(e.target.value)}
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e: ChangeEvent<HTMLInputElement>): void => setEmail(e.target.value)}
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e: ChangeEvent<HTMLInputElement>): void => setPassword(e.target.value)}
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <input
              type="password"
              placeholder="Confirm Password"
              value={confirmPassword}
              onChange={(e: ChangeEvent<HTMLInputElement>): void => setConfirmPassword(e.target.value)}
              disabled={loading}
            />
          </div>

          {error && <div className="error-message">{error}</div>}

          <button type="submit" disabled={loading} className="auth-button">
            {loading ? "Creating account..." : "Sign Up with Email"}
          </button>
        </form>

        <div className="auth-footer">
          <p>
            Already have an account?{" "}
            <Link to="/login" className="auth-link">
              Sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Register;
