# @rezzed.ai/dual-auth

[![npm version](https://img.shields.io/npm/v/@rezzed.ai/dual-auth.svg)](https://www.npmjs.com/package/@rezzed.ai/dual-auth)
[![license](https://img.shields.io/npm/l/@rezzed.ai/dual-auth.svg)](https://github.com/rezzedai/dual-auth/blob/main/LICENSE)
[![node version](https://img.shields.io/node/v/@rezzed.ai/dual-auth.svg)](https://www.npmjs.com/package/@rezzed.ai/dual-auth)

Dual authentication supporting API keys and Firebase tokens, with AES-256 encryption utilities.

## Installation

```bash
npm install @rezzed.ai/dual-auth
```

For Firebase token validation, also install `firebase-admin`:

```bash
npm install firebase-admin
```

## Quick Start

### API Key Authentication

```typescript
import { createDualAuth, hashKey } from "@rezzed.ai/dual-auth";

// Create an API key store (example using in-memory storage)
const apiKeyStore = {
  async getByHash(hash) {
    // Look up the key in your database
    // Return { userId: string, active?: boolean, revokedAt?: Date }
    const key = await db.apiKeys.findOne({ hash });
    return key || null;
  },
  touchLastUsed(hash) {
    // Optional: update last used timestamp
    db.apiKeys.update({ hash }, { lastUsedAt: new Date() });
  }
};

// Create the authenticator
const auth = createDualAuth({ keyStore: apiKeyStore });

// Authenticate a request
const context = await auth.authenticate(apiKey);
if (context) {
  console.log("User ID:", context.userId);
  console.log("Method:", context.method); // "api-key"
  console.log("Encryption key:", context.encryptionKey); // 32-byte Buffer
}
```

### Dual Mode: API Keys + Firebase Tokens

```typescript
import { createDualAuth, createFirebaseValidator } from "@rezzed.ai/dual-auth";
import admin from "firebase-admin";

// Initialize Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

// Create the authenticator with both modes
const auth = createDualAuth({
  keyStore: apiKeyStore,
  tokenValidator: createFirebaseValidator()
});

// Now authenticate accepts both API keys and Firebase JWT tokens
const context = await auth.authenticate(credentialString);
if (context) {
  console.log("User ID:", context.userId);
  console.log("Method:", context.method); // "api-key" or "firebase-token"
  console.log("Metadata:", context.metadata);
}
```

## Encryption Utilities

The library includes AES-256-CBC encryption utilities with PBKDF2 key derivation:

```typescript
import { encrypt, decrypt, isEncrypted, deriveEncryptionKey } from "@rezzed.ai/dual-auth";

// Encrypt/decrypt with a string secret
const plaintext = "sensitive data";
const encrypted = encrypt(plaintext, "my-secret-key");
const decrypted = decrypt(encrypted, "my-secret-key");

// Or use a derived encryption key directly
const key = deriveEncryptionKey("my-secret");
const encrypted2 = encrypt(plaintext, key);
const decrypted2 = decrypt(encrypted2, key);

// Check if a string is encrypted
if (isEncrypted(someString)) {
  const decrypted = decrypt(someString, key);
}
```

### Using the AuthContext Encryption Key

Each authenticated request gets a deterministic encryption key derived from the credential:

```typescript
const context = await auth.authenticate(apiKey);
if (context) {
  // Use the session-specific encryption key
  const encrypted = encrypt("user data", context.encryptionKey);
  const decrypted = decrypt(encrypted, context.encryptionKey);
}
```

## API Reference

### `createDualAuth(options: DualAuthOptions): DualAuth`

Create a new dual authenticator.

**Options:**
- `keyStore: ApiKeyStore` - Required. Store for API key lookups
- `tokenValidator?: TokenValidator` - Optional. Token validator (e.g., Firebase Auth)
- `isToken?: (credential: string) => boolean` - Optional. Custom token detector (default: checks for "eyJ" JWT prefix)
- `saltPrefix?: string` - Optional. Encryption key derivation salt prefix (default: "dual_auth_v1_")

### `DualAuth.authenticate(credential: string): Promise<AuthContext | null>`

Authenticate a credential (API key or token). Returns `AuthContext` on success, `null` on failure.

**AuthContext:**
```typescript
interface AuthContext {
  userId: string;              // Authenticated user ID
  keyHash: string;             // Hash of the API key (or "token:{uid}" for tokens)
  encryptionKey: Buffer;       // 32-byte derived encryption key
  method: "api-key" | "firebase-token";
  metadata?: Record<string, unknown>;
}
```

### `hashKey(input: string): string`

Generate a SHA-256 hex hash of the input string.

### `deriveEncryptionKey(secret: string, saltPrefix?: string): Buffer`

Derive a 32-byte encryption key from a secret using PBKDF2 (100,000 iterations, SHA-256).

### `encrypt(plaintext: string, key: Buffer | string, saltPrefix?: string): string`

Encrypt plaintext using AES-256-CBC. Returns base64-encoded ciphertext with IV prepended.

### `decrypt(ciphertext: string, key: Buffer | string, saltPrefix?: string): string`

Decrypt ciphertext encrypted with `encrypt()`. Throws on decryption failure.

### `isEncrypted(text: string | null | undefined): boolean`

Check if a string appears to be encrypted (base64 with minimum length).

### `createFirebaseValidator(): TokenValidator`

Create a Firebase Auth token validator. Requires `firebase-admin` to be installed and initialized.

## Implementing an API Key Store

The `ApiKeyStore` interface requires:

```typescript
interface ApiKeyStore {
  getByHash(hash: string): Promise<ApiKeyRecord | null>;
  touchLastUsed?(hash: string): void;  // Optional
}

interface ApiKeyRecord {
  userId: string;
  active?: boolean;      // If false, key is rejected
  revokedAt?: Date | null;  // If set, key is rejected
  metadata?: Record<string, unknown>;
}
```

Example with Firestore:

```typescript
const apiKeyStore = {
  async getByHash(hash) {
    const doc = await firestore.collection("apiKeys").doc(hash).get();
    if (!doc.exists) return null;
    return doc.data();
  },
  touchLastUsed(hash) {
    firestore.collection("apiKeys").doc(hash).update({
      lastUsedAt: admin.firestore.FieldValue.serverTimestamp()
    });
  }
};
```

## Custom Token Validators

You can implement custom token validators:

```typescript
const customValidator = {
  async verify(token) {
    try {
      const payload = await yourTokenVerifier(token);
      return { uid: payload.sub, metadata: { email: payload.email } };
    } catch {
      return null;
    }
  }
};

const auth = createDualAuth({
  keyStore: apiKeyStore,
  tokenValidator: customValidator,
  isToken: (cred) => cred.startsWith("custom_")
});
```

## License

MIT License - Copyright (c) 2026 Rezzed.ai

Built by [Rezzed.ai](https://rezzed.ai)
