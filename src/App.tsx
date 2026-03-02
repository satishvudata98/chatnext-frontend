import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Home from "./pages/Home";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Chat from "./pages/Chat";
import ProtectedRoute from "./components/ProtectedRoute";
import { useAuth } from "./context/AuthContext";

export default function App() {
<<<<<<< Updated upstream
  const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(null);

  useEffect(() => {
    const checkAuth = async () => {
      const token = localStorage.getItem("accessToken");
      if (token) {
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
  }, []);

  // Show loading while checking auth
  if (isAuthenticated === null) {
=======
  const { user, loading } = useAuth();
  if (loading) {
>>>>>>> Stashed changes
    return <div>Loading...</div>;
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={user ? <Navigate to="/chat" replace /> : <Home />} />
        <Route path="/login" element={user ? <Navigate to="/chat" replace /> : <Login />} />
        <Route path="/register" element={user ? <Navigate to="/chat" replace /> : <Register />} />
        <Route
          path="/chat"
          element={
            <ProtectedRoute>
              <Chat />
            </ProtectedRoute>
          }
        />
        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </BrowserRouter>
  );
}
