import { useState, useEffect } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Home from "./pages/Home";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Chat from "./pages/Chat";
import { verifyApi } from "./api/api";

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(null);
  const [skipVerify, setSkipVerify] = useState<boolean>(false);

  useEffect(() => {
    const checkAuth = async () => {
      const token = localStorage.getItem("accessToken");
      if (token) {
        // If we just logged in, skip verification (tokens are fresh)
        if (skipVerify) {
          setIsAuthenticated(true);
          setSkipVerify(false);
          return;
        }

        try {
          await verifyApi();
          setIsAuthenticated(true);
        } catch {
          // Token invalid, clear storage
          localStorage.removeItem("accessToken");
          localStorage.removeItem("refreshToken");
          localStorage.removeItem("user");
          setIsAuthenticated(false);
        }
      } else {
        setIsAuthenticated(false);
      }
    };

    checkAuth();

    // Listen for storage changes (tab/window sync + login updates)
    const handleStorageChange = () => {
      checkAuth();
    };

    // Listen for custom login success event - skip verification on fresh login
    const handleLoginSuccess = () => {
      setSkipVerify(true);
      checkAuth();
    };

    globalThis.addEventListener("storage", handleStorageChange);
    globalThis.addEventListener("loginSuccess", handleLoginSuccess);
    return () => {
      globalThis.removeEventListener("storage", handleStorageChange);
      globalThis.removeEventListener("loginSuccess", handleLoginSuccess);
    };
  }, [skipVerify]);

  // Show loading while checking auth
  if (isAuthenticated === null) {
    return <div>Loading...</div>;
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={isAuthenticated ? <Navigate to="/chat" /> : <Home />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/chat" element={isAuthenticated ? <Chat /> : <Navigate to="/login" />} />
        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </BrowserRouter>
  );
}