import { hashKey, deriveEncryptionKey } from "./crypto.js";
import type { AuthContext, DualAuthOptions, ApiKeyStore, TokenValidator } from "./types.js";

/** Default token detector: JWTs start with "eyJ" */
function defaultIsToken(credential: string): boolean {
  return credential.startsWith("eyJ");
}

export class DualAuth {
  private keyStore: ApiKeyStore;
  private tokenValidator?: TokenValidator;
  private isToken: (credential: string) => boolean;
  private saltPrefix?: string;

  constructor(options: DualAuthOptions) {
    this.keyStore = options.keyStore;
    this.tokenValidator = options.tokenValidator;
    this.isToken = options.isToken || defaultIsToken;
    this.saltPrefix = options.saltPrefix;
  }

  async authenticate(credential: string): Promise<AuthContext | null> {
    if (this.tokenValidator && this.isToken(credential)) {
      return this.validateToken(credential);
    }
    return this.validateApiKey(credential);
  }

  private async validateApiKey(apiKey: string): Promise<AuthContext | null> {
    const hash = hashKey(apiKey);
    const record = await this.keyStore.getByHash(hash);
    if (!record) return null;
    if (record.active === false) return null;
    if (record.revokedAt) return null;

    // Fire-and-forget: update last used
    this.keyStore.touchLastUsed?.(hash);

    return {
      userId: record.userId,
      keyHash: hash,
      encryptionKey: deriveEncryptionKey(apiKey, this.saltPrefix),
      method: "api-key",
      metadata: record.metadata,
    };
  }

  private async validateToken(token: string): Promise<AuthContext | null> {
    if (!this.tokenValidator) return null;
    const result = await this.tokenValidator.verify(token);
    if (!result) return null;

    // Derive a deterministic encryption key from the UID
    const encryptionKey = deriveEncryptionKey(result.uid, this.saltPrefix);

    return {
      userId: result.uid,
      keyHash: `token:${result.uid}`,
      encryptionKey,
      method: "firebase-token",
      metadata: result.metadata,
    };
  }
}

export function createDualAuth(options: DualAuthOptions): DualAuth {
  return new DualAuth(options);
}
