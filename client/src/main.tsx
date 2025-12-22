import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";

// Global flag set by React when app is ready
declare global {
  interface Window {
    __KEYLESSH_READY__?: boolean;
  }
}

// Global error handlers to catch any uncaught errors
window.onerror = (message, source, lineno, colno, error) => {
  console.error("[Global Error]", { message, source, lineno, colno, error });
  // If error happens during initialization and page is blank, show recovery
  if (!window.__KEYLESSH_READY__) {
    showRecoveryUI("Uncaught error: " + String(message));
  }
  return false;
};

window.onunhandledrejection = (event) => {
  console.error("[Unhandled Promise Rejection]", event.reason);
  // If error happens during initialization and page is blank, show recovery
  if (!window.__KEYLESSH_READY__) {
    showRecoveryUI("Unhandled promise rejection: " + String(event.reason));
  }
};

function showRecoveryUI(errorMsg: string) {
  const root = document.getElementById("root");
  if (root && !root.querySelector("[data-recovery-ui]")) {
    root.innerHTML = `
      <div data-recovery-ui style="min-height: 100vh; background: #09090b; display: flex; align-items: center; justify-content: center;">
        <div style="text-align: center; color: #a1a1aa; max-width: 400px; padding: 20px;">
          <p style="font-size: 14px; font-family: system-ui, sans-serif; margin-bottom: 16px; color: #ef4444;">
            Application failed to load
          </p>
          <p style="font-size: 12px; font-family: monospace; margin-bottom: 16px; color: #71717a; word-break: break-all;">
            ${errorMsg}
          </p>
          <button
            onclick="localStorage.clear(); sessionStorage.clear(); window.location.href='/login';"
            style="padding: 8px 16px; background: #27272a; color: #fafafa; border: 1px solid #3f3f46; border-radius: 6px; cursor: pointer; font-size: 14px; font-family: system-ui, sans-serif;"
          >
            Clear session and restart
          </button>
        </div>
      </div>
    `;
  }
}

// Check URL for force reset parameter
const params = new URLSearchParams(window.location.search);
if (params.get("reset") === "true") {
  console.warn("[main] Force reset requested via URL parameter");
  localStorage.clear();
  sessionStorage.clear();
  // Remove the reset param and reload
  params.delete("reset");
  const newUrl = params.toString()
    ? `${window.location.pathname}?${params.toString()}`
    : window.location.pathname;
  window.history.replaceState({}, "", newUrl);
  window.location.href = "/login";
}

// Pre-initialization cleanup: detect and clear corrupted auth state
// This runs BEFORE React mounts to prevent TideCloak from hanging
function cleanupCorruptedState() {
  try {
    // Check if our access_token looks valid (basic JWT format check)
    const token = localStorage.getItem("access_token");
    if (token && token.split(".").length !== 3) {
      console.warn("[main] Clearing invalid access_token");
      localStorage.removeItem("access_token");
    }

    // Check for expired JWT tokens - if exp claim is in the past, clear it
    if (token) {
      try {
        const payload = JSON.parse(atob(token.split(".")[1]));
        if (payload.exp && payload.exp * 1000 < Date.now()) {
          console.warn("[main] Clearing expired access_token");
          localStorage.removeItem("access_token");
        }
      } catch {
        // If we can't parse the token, it's invalid
        console.warn("[main] Clearing unparseable access_token");
        localStorage.removeItem("access_token");
      }
    }

    // Check for OIDC/TideCloak state corruption
    // TideCloak stores state with keys like "oidc.*" or "kc-*"
    const suspiciousKeys: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && (key.startsWith("oidc.") || key.startsWith("kc-"))) {
        try {
          const value = localStorage.getItem(key);
          if (value) {
            JSON.parse(value); // Will throw if corrupted
          }
        } catch {
          suspiciousKeys.push(key);
        }
      }
    }

    if (suspiciousKeys.length > 0) {
      console.warn("[main] Clearing corrupted OIDC state:", suspiciousKeys);
      suspiciousKeys.forEach((k) => localStorage.removeItem(k));
    }
  } catch (e) {
    console.error("[main] Error during state cleanup:", e);
  }
}

cleanupCorruptedState();

// Global timeout: if the app hasn't signaled ready in 10 seconds,
// show a recovery button in the initial loader
const INIT_TIMEOUT_MS = 10000;
setTimeout(() => {
  if (!window.__KEYLESSH_READY__) {
    console.warn("[main] App initialization timeout - showing recovery option");
    const loader = document.getElementById("initial-loader");
    if (loader) {
      loader.innerHTML = `
        <div style="text-align: center; color: #a1a1aa;">
          <p style="font-size: 14px; font-family: system-ui, sans-serif; margin-bottom: 16px;">
            Loading is taking longer than expected...
          </p>
          <button
            onclick="localStorage.clear(); sessionStorage.clear(); window.location.href='/login';"
            style="padding: 8px 16px; background: #27272a; color: #fafafa; border: 1px solid #3f3f46; border-radius: 6px; cursor: pointer; font-size: 14px; font-family: system-ui, sans-serif;"
          >
            Clear session and restart
          </button>
        </div>
      `;
    }
  }
}, INIT_TIMEOUT_MS);

createRoot(document.getElementById("root")!).render(<App />);
