import type { TokenValidator } from "./types.js";

/**
 * Create a Firebase Auth token validator.
 * Requires firebase-admin to be installed and initialized.
 */
export function createFirebaseValidator(): TokenValidator {
  // Dynamic import to keep firebase-admin as optional peer dep
  let admin: any;
  try {
    admin = require("firebase-admin");
  } catch {
    throw new Error(
      "@rezzed/dual-auth: firebase-admin is required for Firebase token validation. " +
      "Install it with: npm install firebase-admin"
    );
  }

  return {
    async verify(token: string) {
      try {
        const decoded = await admin.auth().verifyIdToken(token);
        return { uid: decoded.uid, metadata: { email: decoded.email, provider: decoded.firebase?.sign_in_provider } };
      } catch {
        return null;
      }
    },
  };
}
