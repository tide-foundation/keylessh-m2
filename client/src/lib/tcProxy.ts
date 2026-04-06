/**
 * Generates a DPoP proof for TideCloak URLs.
 * Used by apiRequest() to attach X-TC-DPoP header on admin API calls,
 * so the server can forward it to TideCloak with proper DPoP binding.
 */

import { IAMService } from "@tidecloak/js";
import { isDpopEnabled } from "./appFetch";

/**
 * Generate a DPoP proof for a TideCloak admin URL.
 * Returns the proof string, or undefined if DPoP is not available.
 */
export async function generateTcDPoPProof(
  tcUrl: string,
  method: string,
): Promise<string | undefined> {
  if (!isDpopEnabled()) return undefined;

  try {
    const provider = (IAMService as any)._dpopProvider;
    if (!provider?.generateDPoPProof) return undefined;

    const token = await IAMService.getToken();
    return await provider.generateDPoPProof(
      tcUrl,
      method.toUpperCase(),
      token || undefined,
    );
  } catch (e) {
    console.warn("[tcProxy] Failed to generate TideCloak DPoP proof:", e);
    return undefined;
  }
}
