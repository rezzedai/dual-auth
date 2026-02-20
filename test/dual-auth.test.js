import { test } from "node:test";
import assert from "node:assert/strict";
import { hashKey, deriveEncryptionKey, encrypt, decrypt, isEncrypted, DualAuth, createDualAuth } from "../dist/esm/index.js";

test("hashKey produces consistent SHA-256 hex", () => {
  const hash1 = hashKey("test-key-123");
  const hash2 = hashKey("test-key-123");
  assert.equal(hash1, hash2);
  assert.equal(hash1.length, 64); // SHA-256 hex is 64 chars
  assert.match(hash1, /^[0-9a-f]{64}$/);
});

test("deriveEncryptionKey returns 32-byte Buffer", () => {
  const key = deriveEncryptionKey("my-secret");
  assert.ok(Buffer.isBuffer(key));
  assert.equal(key.length, 32);
});

test("encrypt/decrypt round-trip", () => {
  const plaintext = "Hello, World!";
  const secret = "my-secret-key";
  const encrypted = encrypt(plaintext, secret);
  const decrypted = decrypt(encrypted, secret);
  assert.equal(decrypted, plaintext);
});

test("encrypt/decrypt round-trip with Buffer key", () => {
  const plaintext = "Test message";
  const key = deriveEncryptionKey("my-secret");
  const encrypted = encrypt(plaintext, key);
  const decrypted = decrypt(encrypted, key);
  assert.equal(decrypted, plaintext);
});

test("decrypt with wrong key throws", () => {
  const plaintext = "Secret data";
  const encrypted = encrypt(plaintext, "correct-key");
  assert.throws(() => {
    decrypt(encrypted, "wrong-key");
  });
});

test("isEncrypted detects encrypted content", () => {
  const plaintext = "Test";
  const encrypted = encrypt(plaintext, "key");
  assert.equal(isEncrypted(encrypted), true);
  assert.equal(isEncrypted("plain text"), false);
  assert.equal(isEncrypted(""), false);
  assert.equal(isEncrypted(null), false);
  assert.equal(isEncrypted(undefined), false);
});

test("DualAuth validates API key via mock store", async () => {
  const mockStore = {
    async getByHash(hash) {
      if (hash === hashKey("valid-key")) {
        return { userId: "user123", active: true };
      }
      return null;
    },
  };

  const auth = new DualAuth({ keyStore: mockStore });
  const result = await auth.authenticate("valid-key");

  assert.ok(result);
  assert.equal(result.userId, "user123");
  assert.equal(result.method, "api-key");
  assert.ok(Buffer.isBuffer(result.encryptionKey));
  assert.equal(result.encryptionKey.length, 32);
});

test("DualAuth rejects inactive key", async () => {
  const mockStore = {
    async getByHash(hash) {
      if (hash === hashKey("inactive-key")) {
        return { userId: "user123", active: false };
      }
      return null;
    },
  };

  const auth = new DualAuth({ keyStore: mockStore });
  const result = await auth.authenticate("inactive-key");
  assert.equal(result, null);
});

test("DualAuth rejects revoked key", async () => {
  const mockStore = {
    async getByHash(hash) {
      if (hash === hashKey("revoked-key")) {
        return { userId: "user123", active: true, revokedAt: new Date() };
      }
      return null;
    },
  };

  const auth = new DualAuth({ keyStore: mockStore });
  const result = await auth.authenticate("revoked-key");
  assert.equal(result, null);
});

test("DualAuth returns null for unknown key", async () => {
  const mockStore = {
    async getByHash() {
      return null;
    },
  };

  const auth = new DualAuth({ keyStore: mockStore });
  const result = await auth.authenticate("unknown-key");
  assert.equal(result, null);
});

test("DualAuth detects and routes token to tokenValidator", async () => {
  const mockStore = {
    async getByHash() {
      return null;
    },
  };

  const mockValidator = {
    async verify(token) {
      if (token === "eyJmake-jwt-token") {
        return { uid: "firebase-user-123", metadata: { email: "test@example.com" } };
      }
      return null;
    },
  };

  const auth = new DualAuth({ keyStore: mockStore, tokenValidator: mockValidator });
  const result = await auth.authenticate("eyJmake-jwt-token");

  assert.ok(result);
  assert.equal(result.userId, "firebase-user-123");
  assert.equal(result.method, "firebase-token");
  assert.equal(result.keyHash, "token:firebase-user-123");
  assert.ok(Buffer.isBuffer(result.encryptionKey));
  assert.deepEqual(result.metadata, { email: "test@example.com" });
});

test("DualAuth falls back to API key when no tokenValidator", async () => {
  const mockStore = {
    async getByHash(hash) {
      if (hash === hashKey("eyJfake-token-as-key")) {
        return { userId: "user123", active: true };
      }
      return null;
    },
  };

  const auth = new DualAuth({ keyStore: mockStore });
  const result = await auth.authenticate("eyJfake-token-as-key");

  assert.ok(result);
  assert.equal(result.method, "api-key");
});

test("createDualAuth convenience function works", async () => {
  const mockStore = {
    async getByHash(hash) {
      if (hash === hashKey("test-key")) {
        return { userId: "user456", active: true };
      }
      return null;
    },
  };

  const auth = createDualAuth({ keyStore: mockStore });
  const result = await auth.authenticate("test-key");

  assert.ok(result);
  assert.equal(result.userId, "user456");
});

test("touchLastUsed is called when present", async () => {
  let touchedHash = null;
  const mockStore = {
    async getByHash(hash) {
      if (hash === hashKey("tracked-key")) {
        return { userId: "user789", active: true };
      }
      return null;
    },
    touchLastUsed(hash) {
      touchedHash = hash;
    },
  };

  const auth = new DualAuth({ keyStore: mockStore });
  await auth.authenticate("tracked-key");

  assert.equal(touchedHash, hashKey("tracked-key"));
});

test("custom saltPrefix is used for encryption", () => {
  const plaintext = "Test";
  const secret = "secret";
  const customPrefix = "custom_prefix_";

  const encrypted1 = encrypt(plaintext, secret);
  const encrypted2 = encrypt(plaintext, secret, customPrefix);

  // Different salt prefixes should produce different ciphertexts
  assert.notEqual(encrypted1, encrypted2);

  // But each should decrypt correctly with its own prefix
  assert.equal(decrypt(encrypted1, secret), plaintext);
  assert.equal(decrypt(encrypted2, secret, customPrefix), plaintext);
});
