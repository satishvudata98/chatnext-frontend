import { useState } from "react";
import type { FC, ChangeEvent, FormEvent } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import "../styles/auth.css";

const Login: FC = (): JSX.Element => {
  const navigate = useNavigate();
  const { loginWithEmail, loginWithGoogle } = useAuth();

  const [email, setEmail] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const [loadingEmail, setLoadingEmail] = useState<boolean>(false);
  const [loadingGoogle, setLoadingGoogle] = useState<boolean>(false);
  const [error, setError] = useState<string>("");

  const handleEmailLogin = async (e: FormEvent<HTMLFormElement>): Promise<void> => {
    e.preventDefault();
    setError("");

    if (!email.trim() || !password.trim()) {
      setError("Email and password are required");
      return;
    }

    setLoadingEmail(true);
    try {
<<<<<<< Updated upstream
      const data = await loginApi(username, password);
      const loginData = data as { success: boolean; accessToken: string; refreshToken: string; user: { id: string; username: string; email: string } };

      if (loginData.success && loginData.accessToken) {
        // Store authentication tokens and user info
        localStorage.setItem("accessToken", loginData.accessToken);
        localStorage.setItem("refreshToken", loginData.refreshToken);
        localStorage.setItem("user", JSON.stringify(loginData.user));
        navigate("/chat");
      } else {
        setError((data as { message?: string }).message || "Invalid login credentials");
      }
=======
      await loginWithEmail(email.trim(), password);
      sessionStorage.setItem("tempPassword", password);
      navigate("/chat");
>>>>>>> Stashed changes
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to sign in");
    } finally {
      setLoadingEmail(false);
    }
  };

  const handleGoogleLogin = async (): Promise<void> => {
    setError("");
    setLoadingGoogle(true);
    try {
      sessionStorage.removeItem("tempPassword");
      await loginWithGoogle();
      navigate("/chat");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Google sign-in failed");
    } finally {
      setLoadingGoogle(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="auth-header">
          <h2>Welcome Back</h2>
          <p>Sign in with Firebase to continue chatting</p>
        </div>

        <form onSubmit={handleEmailLogin} className="auth-form">
          <div className="form-group">
            <input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e: ChangeEvent<HTMLInputElement>): void => setEmail(e.target.value)}
              disabled={loadingEmail || loadingGoogle}
            />
          </div>

          <div className="form-group">
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e: ChangeEvent<HTMLInputElement>): void => setPassword(e.target.value)}
              disabled={loadingEmail || loadingGoogle}
            />
          </div>

          {error && <div className="error-message">{error}</div>}

          <button type="submit" disabled={loadingEmail || loadingGoogle} className="auth-button">
            {loadingEmail ? "Signing in..." : "Sign In with Email"}
          </button>
        </form>

        <button
          type="button"
          disabled={loadingEmail || loadingGoogle}
          onClick={handleGoogleLogin}
          className="auth-button secondary google-button"
        >
          {loadingGoogle ? "Connecting..." : "Continue with Google"}
        </button>

        <div className="auth-footer">
          <p>
            Don&apos;t have an account?{" "}
            <Link to="/register" className="auth-link">
              Create one
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Login;
