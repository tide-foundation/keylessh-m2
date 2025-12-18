import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from "react";
import { TideCloakContextProvider, useTideCloak } from "@tidecloak/react";
import type { OIDCUser, UserRole, AuthState } from "@shared/schema";
import adapter from "../tidecloakAdapter.json";

interface AuthContextValue extends AuthState {
  login: () => void;
  logout: () => void;
  getToken: () => string | null;
  hasRole: (role: UserRole) => boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

const tidecloakConfig = {
  ...adapter,
  redirectUri: `${window.location.origin}/auth/redirect`,
};

function TideCloakAuthBridge({ children }: { children: ReactNode }) {
  const tidecloak = useTideCloak();
  const [state, setState] = useState<AuthState>({
    user: null,
    accessToken: null,
    isAuthenticated: false,
    isLoading: true,
  });

  useEffect(() => {
    if (!tidecloak.isInitializing) {
      if (tidecloak.authenticated) {
        const user: OIDCUser = {
          id: tidecloak.getValueFromIdToken("sub") || "",
          username: tidecloak.getValueFromIdToken("preferred_username") ||
                    tidecloak.getValueFromIdToken("name") || "",
          email: tidecloak.getValueFromIdToken("email") || "",
          role: tidecloak.hasClientRole("tide-realm-admin", "realm-management") ? "admin" : "user",
          allowedServers: (tidecloak.getValueFromIdToken("allowed_servers") as string[]) || [],
        };

        // Store token in localStorage for API calls
        if (tidecloak.token) {
          localStorage.setItem("access_token", tidecloak.token);
        }

        setState({
          user,
          accessToken: tidecloak.token || null,
          isAuthenticated: true,
          isLoading: false,
        });
      } else {
        // Clear token from localStorage
        localStorage.removeItem("access_token");

        setState({
          user: null,
          accessToken: null,
          isAuthenticated: false,
          isLoading: false,
        });
      }
    }
  }, [tidecloak.isInitializing, tidecloak.authenticated, tidecloak]);

  const login = useCallback(() => {
    tidecloak.login();
  }, [tidecloak]);

  const logout = useCallback(() => {
    localStorage.removeItem("access_token");
    tidecloak.logout();
  }, [tidecloak]);

  const getToken = useCallback(() => {
    return tidecloak.token || null;
  }, [tidecloak]);

  const hasRole = useCallback(
    (role: UserRole) => {
      if (role === "admin") {
        return tidecloak.hasClientRole("tide-realm-admin", "realm-management");
      }
      return state.isAuthenticated;
    },
    [tidecloak, state.isAuthenticated]
  );

  return (
    <AuthContext.Provider value={{ ...state, login, logout, getToken, hasRole }}>
      {children}
    </AuthContext.Provider>
  );
}

export function AuthProvider({ children }: { children: ReactNode }) {
  return (
    <TideCloakContextProvider config={tidecloakConfig}>
      <TideCloakAuthBridge>{children}</TideCloakAuthBridge>
    </TideCloakContextProvider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
}

export { useTideCloak };
