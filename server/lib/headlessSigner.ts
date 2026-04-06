/**
 * Headless browser DPoP signer.
 *
 * Launches a minimal Chromium instance that:
 * 1. Loads a tiny page with @tidecloak/js
 * 2. Authenticates via client credentials (service account)
 * 3. Gets a DPoP-bound access token
 * 4. Signs DPoP proofs on demand using crypto.subtle.sign
 *
 * One browser instance is shared across all requests.
 * The browser auto-refreshes tokens.
 */

import { getAuthOverrideUrl, getRealm, getResource } from "./auth/tidecloakConfig";

let browser: any = null;
let page: any = null;
let ready = false;
let startupPromise: Promise<void> | null = null;

/**
 * Get or create the headless signer.
 * Lazy-initialized on first use.
 */
async function ensureBrowser(): Promise<void> {
  if (ready) return;
  if (startupPromise) return startupPromise;

  startupPromise = (async () => {
    try {
      // Dynamic import — puppeteer is optional dependency
      const puppeteer = await import("puppeteer");

      browser = await puppeteer.launch({
        headless: true,
        args: [
          "--no-sandbox",
          "--disable-setuid-sandbox",
          "--disable-dev-shm-usage", // Use /tmp instead of /dev/shm (Azure has small /dev/shm)
          "--disable-gpu",
          "--disable-extensions",
          "--disable-background-networking",
          "--disable-default-apps",
          "--disable-sync",
          "--disable-translate",
          "--single-process", // Reduces memory
          "--no-zygote",
        ],
      });

      page = await browser.newPage();

      // Block unnecessary resources to minimize memory
      await page.setRequestInterception(true);
      page.on("request", (req: any) => {
        const type = req.resourceType();
        if (["image", "stylesheet", "font", "media"].includes(type)) {
          req.abort();
        } else {
          req.continue();
        }
      });

      // Build the TideCloak auth URL for service account login
      const authUrl = getAuthOverrideUrl();
      const realm = getRealm();
      const clientId = getResource();

      // Load a minimal page that initializes TideCloak DPoP
      const signerHtml = buildSignerPage(authUrl, realm, clientId);
      await page.setContent(signerHtml, { waitUntil: "networkidle0" });

      // Wait for TideCloak to initialize and login
      await page.waitForFunction("window.__dpopReady === true", { timeout: 30000 });

      ready = true;
      console.log("[HeadlessSigner] DPoP signer ready");
    } catch (e) {
      console.error("[HeadlessSigner] Failed to start:", e);
      startupPromise = null;
      throw e;
    }
  })();

  return startupPromise;
}

/**
 * Generate a DPoP proof for a TideCloak URL.
 * Uses the headless browser's Heimdall key.
 */
export async function generateDPoPProof(
  url: string,
  method: string,
  accessToken?: string,
): Promise<string | undefined> {
  try {
    await ensureBrowser();
    if (!page) return undefined;

    const proof = await page.evaluate(
      async (url: string, method: string, token: string | undefined) => {
        return await (window as any).__generateDPoPProof(url, method, token);
      },
      url,
      method.toUpperCase(),
      accessToken,
    );

    return proof as string;
  } catch (e) {
    console.error("[HeadlessSigner] Proof generation failed:", e);
    return undefined;
  }
}

/**
 * Get the current access token from the headless browser.
 */
export async function getAccessToken(): Promise<string | undefined> {
  try {
    await ensureBrowser();
    if (!page) return undefined;

    return await page.evaluate(() => {
      return (window as any).__getAccessToken();
    }) as string;
  } catch {
    return undefined;
  }
}

/**
 * Shutdown the headless browser.
 */
export async function shutdown(): Promise<void> {
  if (browser) {
    await browser.close();
    browser = null;
    page = null;
    ready = false;
    startupPromise = null;
  }
}

/**
 * Build a minimal HTML page that initializes TideCloak with DPoP.
 * No React, no UI — just the auth logic.
 */
function buildSignerPage(authUrl: string, realm: string, clientId: string): string {
  return `<!DOCTYPE html>
<html><head><title>DPoP Signer</title></head>
<body>
<script>
  window.__dpopReady = false;
  window.__accessToken = null;
  window.__dpopKeys = null;

  // Base64URL encode
  function b64url(buf) {
    const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
    return btoa(String.fromCharCode(...bytes))
      .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  }

  // Generate EdDSA key pair for DPoP
  async function initDPoP() {
    try {
      // Generate a fresh EdDSA key pair for this server instance
      const keyPair = await crypto.subtle.generateKey(
        { name: "Ed25519" },
        false, // not extractable (private key stays in browser)
        ["sign", "verify"]
      );

      window.__dpopKeys = keyPair;

      // Get public key as JWK for DPoP headers
      const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
      window.__dpopPublicJwk = { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x };

      // Now authenticate with TideCloak using client credentials
      // The DPoP proof is included in the token request
      const tokenUrl = "${authUrl}/realms/${realm}/protocol/openid-connect/token";

      // Generate DPoP proof for token endpoint
      const proof = await generateProof(tokenUrl, "POST");

      const body = new URLSearchParams({
        grant_type: "client_credentials",
        client_id: "${clientId}",
      });

      const resp = await fetch(tokenUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "DPoP": proof,
        },
        body: body.toString(),
      });

      if (resp.ok) {
        const data = await resp.json();
        window.__accessToken = data.access_token;

        // Auto-refresh token before expiry
        const expiresIn = data.expires_in || 300;
        setInterval(async () => {
          try {
            const refreshProof = await generateProof(tokenUrl, "POST");
            const refreshResp = await fetch(tokenUrl, {
              method: "POST",
              headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                "DPoP": refreshProof,
              },
              body: body.toString(),
            });
            if (refreshResp.ok) {
              const refreshData = await refreshResp.json();
              window.__accessToken = refreshData.access_token;
            }
          } catch (e) { console.error("Token refresh failed:", e); }
        }, (expiresIn - 30) * 1000); // Refresh 30s before expiry

        window.__dpopReady = true;
      } else {
        const err = await resp.text();
        console.error("Token request failed:", resp.status, err);
        // Still mark as ready — will use Bearer fallback
        window.__dpopReady = true;
      }
    } catch (e) {
      console.error("DPoP init failed:", e);
      window.__dpopReady = true; // Mark ready even on failure — Bearer fallback
    }
  }

  async function generateProof(url, method, accessToken) {
    const header = {
      typ: "dpop+jwt",
      alg: "EdDSA",
      jwk: window.__dpopPublicJwk,
    };

    const payload = {
      jti: crypto.randomUUID(),
      htm: method,
      htu: url.split("?")[0],
      iat: Math.floor(Date.now() / 1000),
    };

    if (accessToken) {
      // Add ath (access token hash) for resource server calls
      const tokenHash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(accessToken));
      payload.ath = b64url(tokenHash);
    }

    const enc = new TextEncoder();
    const headerB64 = b64url(enc.encode(JSON.stringify(header)));
    const payloadB64 = b64url(enc.encode(JSON.stringify(payload)));
    const sigInput = enc.encode(headerB64 + "." + payloadB64);

    const sig = await crypto.subtle.sign({ name: "Ed25519" }, window.__dpopKeys.privateKey, sigInput);
    return headerB64 + "." + payloadB64 + "." + b64url(sig);
  }

  // Exposed functions for Puppeteer evaluate()
  window.__generateDPoPProof = async function(url, method, accessToken) {
    if (!window.__dpopKeys) throw new Error("DPoP not initialized");
    return await generateProof(url, method, accessToken || window.__accessToken);
  };

  window.__getAccessToken = function() {
    return window.__accessToken;
  };

  // Start
  initDPoP();
</script>
</body></html>`;
}
