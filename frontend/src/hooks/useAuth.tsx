import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { jwtDecode } from "jwt-decode";
import { setAccessToken } from "@/api/client";
import { login as loginApi, register as registerApi } from "@/api/auth";
import type { LoginPayload, RegisterPayload, User } from "@/api/schemas";

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (payload: LoginPayload) => Promise<void>;
  register: (payload: RegisterPayload) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthState | null>(null);

interface JwtPayload {
  user_id: number;
  username?: string;
  email?: string;
  role?: string;
  exp: number;
}

function userFromToken(token: string): User | null {
  try {
    const decoded = jwtDecode<JwtPayload>(token);
    return {
      id: decoded.user_id,
      username: decoded.username ?? "user",
      email: decoded.email ?? "",
      role: (decoded.role as User["role"]) ?? "viewer",
    };
  } catch {
    return null;
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const refresh = sessionStorage.getItem("refresh_token");
    const savedUser = sessionStorage.getItem("user");
    if (refresh && savedUser) {
      try {
        const parsed = JSON.parse(savedUser) as User;
        setUser(parsed);
        /* Try to use saved access token */
        const savedAccess = sessionStorage.getItem("access_token");
        if (savedAccess) {
          setAccessToken(savedAccess);
        }
      } catch {
        sessionStorage.clear();
      }
    }
    setIsLoading(false);
  }, []);

  const login = useCallback(async (payload: LoginPayload) => {
    const data = await loginApi(payload);
    setAccessToken(data.access);
    sessionStorage.setItem("refresh_token", data.refresh);
    sessionStorage.setItem("access_token", data.access);
    const u = (data as any).user || userFromToken(data.access);
    if (u) {
      setUser(u);
      sessionStorage.setItem("user", JSON.stringify(u));
    }
  }, []);

  const register = useCallback(async (payload: RegisterPayload) => {
    const data = await registerApi(payload);
    /* After registration, set user but don't auto-login (no tokens returned) */
    const u: User = {
      id: data.user.id,
      username: data.user.username,
      email: data.user.email,
      role: data.user.role as User["role"],
    };
    setUser(u);
  }, []);

  const logout = useCallback(() => {
    setAccessToken(null);
    setUser(null);
    sessionStorage.removeItem("refresh_token");
    sessionStorage.removeItem("access_token");
    sessionStorage.removeItem("user");
  }, []);

  const value = useMemo(
    () => ({
      user,
      isAuthenticated: !!user && !!sessionStorage.getItem("refresh_token"),
      isLoading,
      login,
      register,
      logout,
    }),
    [user, isLoading, login, register, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
