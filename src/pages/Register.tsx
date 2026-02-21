import { useState } from "react";
import type { FC, ChangeEvent, FormEvent } from "react";
import { useNavigate, Link } from "react-router-dom";
import { registerApi } from "../api/api";
import "../styles/auth.css";

const Register: FC = (): JSX.Element => {
  const navigate = useNavigate();
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

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setError("Invalid email format");
      return;
    }

    setLoading(true);
    try {
      const data = await registerApi(username, email, password);
      const loginData = data as { success: boolean; token: string; user: { id: string; username: string; email: string } };

      if (loginData.success && loginData.token) {
        // Store token and user info, then redirect to chat
        localStorage.setItem("token", loginData.token);
        localStorage.setItem("user", JSON.stringify(loginData.user));
        navigate("/chat");
      } else {
        setError((data as { message?: string }).message || "User already exists");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Connection error. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent<HTMLInputElement>): void => {
    if (e.key === "Enter") {
      handleRegister(e as unknown as FormEvent<HTMLFormElement>);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="auth-header">
          <h2>Create Account</h2>
          <p>Join ChatNext and start messaging</p>
        </div>

        <form onSubmit={handleRegister} className="auth-form">
          <div className="form-group">
            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={(e: ChangeEvent<HTMLInputElement>): void => setUsername(e.target.value)}
              onKeyPress={handleKeyPress}
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e: ChangeEvent<HTMLInputElement>): void => setEmail(e.target.value)}
              onKeyPress={handleKeyPress}
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e: ChangeEvent<HTMLInputElement>): void => setPassword(e.target.value)}
              onKeyPress={handleKeyPress}
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <input
              type="password"
              placeholder="Confirm Password"
              value={confirmPassword}
              onChange={(e: ChangeEvent<HTMLInputElement>): void => setConfirmPassword(e.target.value)}
              onKeyPress={handleKeyPress}
              disabled={loading}
            />
          </div>

          {error && <div className="error-message">{error}</div>}

          <button
            type="submit"
            disabled={loading}
            className="auth-button"
          >
            {loading ? "Creating account..." : "Create Account"}
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
}

export default Register;