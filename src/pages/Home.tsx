import { useNavigate } from "react-router-dom";
import "../styles/auth.css";

export default function Home() {
  const navigate = useNavigate();

  return (
    <div className="auth-container">
      <div className="home-card">
        <div className="logo-section">
          <div className="logo-icon">💬</div>
          <h1 className="logo">ChatNext</h1>
          <p className="tagline">Real-time messaging made simple</p>
        </div>

        <div className="auth-buttons">
          <button
            onClick={() => navigate("/login")}
            className="auth-button primary"
          >
            Sign In
          </button>
          <button
            onClick={() => navigate("/register")}
            className="auth-button secondary"
          >
            Create Account
          </button>
        </div>

        <div className="home-features">
          <div className="feature">
            <span>⚡</span>
            <p>Lightning Fast</p>
          </div>
          <div className="feature">
            <span>🔒</span>
            <p>Secure</p>
          </div>
          <div className="feature">
            <span>📱</span>
            <p>Mobile Ready</p>
          </div>
        </div>
      </div>
    </div>
  );
}