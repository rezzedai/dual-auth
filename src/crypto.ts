import crypto from "crypto";

const DEFAULT_SALT_PREFIX = "dual_auth_v1_";
const KEY_ITERATIONS = 100000;
const KEY_LENGTH = 32;
const IV_LENGTH = 16;
const ALGORITHM = "aes-256-cbc";

export function hashKey(input: string): string {
  return crypto.createHash("sha256").update(input).digest("hex");
}

export function deriveEncryptionKey(secret: string, saltPrefix?: string): Buffer {
  const prefix = saltPrefix || DEFAULT_SALT_PREFIX;
  const hash = hashKey(secret);
  const salt = prefix + hash.substring(0, 16);
  return crypto.pbkdf2Sync(secret, salt, KEY_ITERATIONS, KEY_LENGTH, "sha256");
}

export function encrypt(plaintext: string, key: Buffer | string, saltPrefix?: string): string {
  const derivedKey = Buffer.isBuffer(key) ? key : deriveEncryptionKey(key, saltPrefix);
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, derivedKey, iv);
  let encrypted = cipher.update(plaintext, "utf8");
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return Buffer.concat([iv, encrypted]).toString("base64");
}

export function decrypt(ciphertext: string, key: Buffer | string, saltPrefix?: string): string {
  const derivedKey = Buffer.isBuffer(key) ? key : deriveEncryptionKey(key, saltPrefix);
  const combined = Buffer.from(ciphertext, "base64");
  if (combined.length < IV_LENGTH + 1) throw new Error("Ciphertext too short");
  const iv = combined.subarray(0, IV_LENGTH);
  const encrypted = combined.subarray(IV_LENGTH);
  const decipher = crypto.createDecipheriv(ALGORITHM, derivedKey, iv);
  let decrypted = decipher.update(encrypted);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString("utf8");
}

export function isEncrypted(text: string | null | undefined): boolean {
  if (!text) return false;
  try {
    const decoded = Buffer.from(text, "base64");
    return decoded.length >= 32;
  } catch {
    return false;
  }
}
