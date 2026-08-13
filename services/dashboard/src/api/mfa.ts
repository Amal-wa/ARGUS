import { ApiError } from "./client";
import type { AuthFetch } from "./monitoring";

// The known non-success `detail` values POST /mfa/challenge/verify can
// return -- see app/routers/mfa.py's MfaVerificationStatus branches. Kept as
// a distinct error type (not just ApiError) so a caller (AuditView) can show
// a precise message per reason rather than a generic "verification failed".
export class MfaVerificationError extends ApiError {
  detail: string;

  constructor(status: number, detail: string) {
    super(status, detail);
    this.detail = detail;
  }
}

export interface MfaVerifyResult {
  decision: "allow" | "deny";
}

export async function verifyMfaChallenge(authFetch: AuthFetch, challengeId: string, code: string): Promise<MfaVerifyResult> {
  const response = await authFetch("/mfa/challenge/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ challenge_id: challengeId, code }),
  });

  if (!response.ok) {
    let detail = "verification_failed";
    try {
      const body: unknown = await response.json();
      const parsed = (body as { detail?: unknown })?.detail;
      if (typeof parsed === "string") detail = parsed;
    } catch {
      // Non-JSON body -- keep the generic detail above.
    }
    throw new MfaVerificationError(response.status, detail);
  }

  return (await response.json()) as MfaVerifyResult;
}
