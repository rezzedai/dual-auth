export interface AuthContext {
  /** Authenticated user ID */
  userId: string;
  /** Hash of the API key (or "firebase:{uid}" for token auth) */
  keyHash: string;
  /** Derived encryption key for the session */
  encryptionKey: Buffer;
  /** Authentication method used */
  method: "api-key" | "firebase-token";
  /** Additional metadata from the auth source */
  metadata?: Record<string, unknown>;
}

export interface ApiKeyRecord {
  userId: string;
  active?: boolean;
  revokedAt?: Date | null;
  metadata?: Record<string, unknown>;
}

export interface ApiKeyStore {
  /** Look up a key record by its SHA-256 hash */
  getByHash(hash: string): Promise<ApiKeyRecord | null>;
  /** Update the lastUsedAt timestamp (fire-and-forget) */
  touchLastUsed?(hash: string): void;
}

export interface TokenValidator {
  /** Verify a JWT/token and return uid + metadata */
  verify(token: string): Promise<{ uid: string; metadata?: Record<string, unknown> } | null>;
}

export interface DualAuthOptions {
  /** Store for API key lookups */
  keyStore: ApiKeyStore;
  /** Token validator (e.g., Firebase Auth) */
  tokenValidator?: TokenValidator;
  /** Function to detect token type. Default: checks for "eyJ" prefix (JWT) */
  isToken?: (credential: string) => boolean;
  /** Encryption key derivation salt prefix. Default: "dual_auth_v1_" */
  saltPrefix?: string;
}
