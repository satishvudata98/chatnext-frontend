import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import type { ReactNode } from "react";
import {
  createUserWithEmailAndPassword,
  onIdTokenChanged,
  signInWithEmailAndPassword,
  signInWithPopup,
  signOut,
  updateProfile,
} from "firebase/auth";
import type { User as FirebaseUser } from "firebase/auth";
import { config } from "../config/config";
import { auth, googleProvider } from "../lib/firebase";

export interface AppUser {
  id: string;
  username: string;
  email: string;
  avatar_url?: string | null;
}

interface AuthContextValue {
  user: AppUser | null;
  firebaseUser: FirebaseUser | null;
  token: string | null;
  loading: boolean;
  loginWithGoogle: () => Promise<void>;
  loginWithEmail: (email: string, password: string) => Promise<void>;
  signupWithEmail: (email: string, password: string, displayName?: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

async function syncUserWithBackend(idToken: string): Promise<AppUser> {
  const res = await fetch(`${config.apiUrl}/api/auth/verify`, {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${idToken}`,
    },
  });

  const data = await res.json();
  if (!res.ok || !data?.success || !data?.user) {
    throw new Error(data?.message || "Failed to verify Firebase session");
  }

  return data.user as AppUser;
}

export function AuthProvider({ children }: { children: ReactNode }): JSX.Element {
  const [user, setUser] = useState<AppUser | null>(null);
  const [firebaseUser, setFirebaseUser] = useState<FirebaseUser | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const clearAuthCache = useCallback(() => {
    localStorage.removeItem("firebaseToken");
    localStorage.removeItem("user");
    localStorage.removeItem("accessToken");
    localStorage.removeItem("refreshToken");
  }, []);

  useEffect(() => {
    const unsubscribe = onIdTokenChanged(auth, async (currentUser) => {
      if (!currentUser) {
        setFirebaseUser(null);
        setToken(null);
        setUser(null);
        clearAuthCache();
        setLoading(false);
        return;
      }

      try {
        const idToken = await currentUser.getIdToken();
        const internalUser = await syncUserWithBackend(idToken);

        setFirebaseUser(currentUser);
        setToken(idToken);
        setUser(internalUser);

        localStorage.setItem("firebaseToken", idToken);
        localStorage.setItem("user", JSON.stringify(internalUser));
      } catch (error) {
        console.error("Auth sync failed:", error);
        await signOut(auth);
      } finally {
        setLoading(false);
      }
    });

    return () => unsubscribe();
  }, [clearAuthCache]);

  const loginWithGoogle = useCallback(async (): Promise<void> => {
    await signInWithPopup(auth, googleProvider);
  }, []);

  const loginWithEmail = useCallback(
    async (email: string, password: string): Promise<void> => {
      await signInWithEmailAndPassword(auth, email, password);
    },
    [],
  );

  const signupWithEmail = useCallback(
    async (email: string, password: string, displayName?: string): Promise<void> => {
      const credential = await createUserWithEmailAndPassword(auth, email, password);
      if (displayName?.trim()) {
        await updateProfile(credential.user, { displayName: displayName.trim() });
      }
    },
    [],
  );

  const logout = useCallback(async (): Promise<void> => {
    await signOut(auth);
    clearAuthCache();
  }, [clearAuthCache]);

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      firebaseUser,
      token,
      loading,
      loginWithGoogle,
      loginWithEmail,
      signupWithEmail,
      logout,
    }),
    [user, firebaseUser, token, loading, loginWithGoogle, loginWithEmail, signupWithEmail, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
}
